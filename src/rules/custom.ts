import fg from 'fast-glob';
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z, ZodError } from 'zod';
import type { ASTNode, Language, Pattern, PatternArgument, RuleDefinition, Severity, SuspiciousNode } from '../types/index.js';
import type { BuiltInRule, RuleCheckContext } from './engine.js';

export interface ValidatedCustomRules {
  files: string[];
  definitions: RuleDefinition[];
  sources: Record<string, string>;
}

const LANGUAGE_VALUES = ['javascript', 'typescript', 'python', 'go'] as const;
const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low'] as const;
const CATEGORY_VALUES = ['injection', 'xss', 'auth', 'path', 'data', 'config', 'ssrf'] as const;
const NODE_TYPE_VALUES = [
  'function_call',
  'string_concat',
  'template_string',
  'assignment',
  'import',
  'function_def',
  'class_def',
  'binary_op',
  'member_access',
  'identifier',
  'literal',
  'unknown',
] as const;

const PatternArgumentSchema = z.object({
  type: z.enum(NODE_TYPE_VALUES),
  operator: z.string().optional(),
  hasExpressions: z.boolean().optional(),
});

const FunctionPatternSchema = z.object({
  match: z.array(z.string().min(1)).min(1),
  on: z.array(z.string().min(1)).min(1).optional(),
});

const PatternSchema = z.object({
  type: z.enum(NODE_TYPE_VALUES).optional(),
  function: FunctionPatternSchema.optional(),
  arguments: z.array(PatternArgumentSchema).min(1).optional(),
  operator: z.string().optional(),
  hasExpressions: z.boolean().optional(),
}).superRefine((pattern, ctx) => {
  if (
    !pattern.type
    && !pattern.function
    && !pattern.arguments?.length
    && pattern.operator === undefined
    && pattern.hasExpressions === undefined
  ) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Pattern must define at least one matcher',
    });
  }
});

const RuleDefinitionSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  severity: z.enum(SEVERITY_VALUES),
  category: z.enum(CATEGORY_VALUES),
  languages: z.array(z.enum(LANGUAGE_VALUES)).min(1),
  description: z.string().min(1),
  patterns: z.array(PatternSchema).min(1),
  exclude: z.array(PatternSchema).min(1).optional(),
});

const RuleFileSchema = z.union([
  RuleDefinitionSchema,
  z.array(RuleDefinitionSchema).min(1),
  z.object({
    rules: z.array(RuleDefinitionSchema).min(1),
  }),
]);

export async function validateCustomRules(customPath: string, existingRuleIds: string[] = []): Promise<ValidatedCustomRules> {
  const files = await resolveCustomRuleFiles(customPath);
  const seenIds = new Map<string, string>(
    existingRuleIds.map(id => [id, 'built-in rules']),
  );
  const definitions: RuleDefinition[] = [];
  const sources: Record<string, string> = {};

  for (const filePath of files) {
    const fileDefinitions = await loadRuleDefinitionsFromFile(filePath);

    for (const definition of fileDefinitions) {
      const existingSource = seenIds.get(definition.id);
      if (existingSource) {
        throw new Error(
          `Duplicate custom rule ID "${definition.id}" in ${filePath}; already defined in ${existingSource}`,
        );
      }

      seenIds.set(definition.id, filePath);
      definitions.push(definition);
      sources[definition.id] = filePath;
    }
  }

  return { files, definitions, sources };
}

export async function loadCustomRules(customPath: string | undefined, existingRuleIds: string[] = []): Promise<BuiltInRule[]> {
  if (!customPath) {
    return [];
  }

  const validated = await validateCustomRules(customPath, existingRuleIds);
  return validated.definitions.map(definition => compileRule(definition, validated.sources[definition.id]));
}

async function resolveCustomRuleFiles(customPath: string): Promise<string[]> {
  const resolvedPath = resolve(customPath);
  const entry = await stat(resolvedPath).catch(() => null);

  if (!entry) {
    throw new Error(`Custom rules path not found: ${resolvedPath}`);
  }

  if (entry.isFile()) {
    return [resolvedPath];
  }

  if (!entry.isDirectory()) {
    throw new Error(`Custom rules path must be a file or directory: ${resolvedPath}`);
  }

  const files = await fg(['**/*.yml', '**/*.yaml'], {
    cwd: resolvedPath,
    absolute: true,
    onlyFiles: true,
  });

  if (files.length === 0) {
    throw new Error(`No YAML custom rule files found in directory: ${resolvedPath}`);
  }

  return files.sort();
}

async function loadRuleDefinitionsFromFile(filePath: string): Promise<RuleDefinition[]> {
  const source = await readFile(filePath, 'utf-8');

  let parsed: unknown;
  try {
    parsed = parseYaml(source);
  } catch (error) {
    throw new Error(`Failed to parse custom rules file ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
  }

  let validated: z.infer<typeof RuleFileSchema>;
  try {
    validated = RuleFileSchema.parse(parsed);
  } catch (error) {
    if (error instanceof ZodError) {
      throw new Error(`Invalid custom rules in ${filePath}: ${formatZodError(error)}`);
    }
    throw error;
  }

  if (Array.isArray(validated)) {
    return validated as RuleDefinition[];
  }

  if ('rules' in validated) {
    return validated.rules as RuleDefinition[];
  }

  return [validated as RuleDefinition];
}

function formatZodError(error: ZodError): string {
  return error.issues
    .map(issue => {
      const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
      return `${path}: ${issue.message}`;
    })
    .join('; ');
}

function compileRule(definition: RuleDefinition, sourceFile: string): BuiltInRule {
  return {
    id: definition.id,
    name: definition.name,
    severity: definition.severity as Severity,
    category: definition.category,
    languages: definition.languages as Language[],
    description: definition.description,
    check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
      if (!matchesAnyPattern(node, ctx, definition.patterns)) {
        return null;
      }

      if (definition.exclude && matchesAnyPattern(node, ctx, definition.exclude)) {
        return null;
      }

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: definition.id,
        ruleName: definition.name,
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.7,
        metadata: {
          category: definition.category,
          source: 'custom',
          ruleSource: sourceFile,
        },
      };
    },
  };
}

function matchesAnyPattern(node: ASTNode, ctx: RuleCheckContext, patterns: Pattern[]): boolean {
  return patterns.some(pattern => matchesPattern(node, ctx, pattern));
}

function matchesPattern(node: ASTNode, ctx: RuleCheckContext, pattern: Pattern): boolean {
  if (pattern.type && node.type !== pattern.type) {
    return false;
  }

  if (pattern.function) {
    if (node.type !== 'function_call') {
      return false;
    }

    const call = ctx.extractCallInfo(node);
    if (!call) {
      return false;
    }

    if (!pattern.function.match.includes(call.name)) {
      return false;
    }

    if (pattern.function.on?.length) {
      if (!call.object) {
        return false;
      }

      const matchesObject = pattern.function.on.some(target =>
        call.object === target || call.object.includes(target),
      );

      if (!matchesObject) {
        return false;
      }
    }
  }

  if (pattern.arguments?.length) {
    if (node.type !== 'function_call') {
      return false;
    }

    const allArgumentsMatch = pattern.arguments.every(argumentPattern =>
      node.children.some(child => matchesArgument(child, argumentPattern)),
    );

    if (!allArgumentsMatch) {
      return false;
    }
  }

  if (pattern.operator !== undefined && !matchesOperator(node, pattern.operator)) {
    return false;
  }

  if (pattern.hasExpressions !== undefined && !matchesHasExpressions(node, pattern.hasExpressions)) {
    return false;
  }

  return true;
}

function matchesArgument(node: ASTNode, pattern: PatternArgument): boolean {
  if (node.type !== pattern.type) {
    return false;
  }

  if (pattern.operator !== undefined && !matchesOperator(node, pattern.operator)) {
    return false;
  }

  if (pattern.hasExpressions !== undefined && !matchesHasExpressions(node, pattern.hasExpressions)) {
    return false;
  }

  return true;
}

function matchesOperator(node: ASTNode, operator: string): boolean {
  if (node.type !== 'string_concat') {
    return false;
  }

  return operator === '+';
}

function matchesHasExpressions(node: ASTNode, expected: boolean): boolean {
  const actual = getHasExpressions(node);
  return actual === expected;
}

function getHasExpressions(node: ASTNode): boolean {
  if (node.type === 'function_call') {
    return node.children.some(child => getHasExpressions(child));
  }

  if (node.type === 'string_concat') {
    return true;
  }

  if (node.type === 'template_string') {
    if (node.rawType === 'f_string') {
      return /\{[^{}]+\}/.test(node.text);
    }

    return node.text.includes('${');
  }

  return false;
}
