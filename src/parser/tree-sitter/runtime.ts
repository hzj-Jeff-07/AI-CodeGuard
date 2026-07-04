import * as TreeSitter from 'web-tree-sitter';
import type { Language as CodeLanguage } from '../../types/index.js';
import { resolveCoreWasmPath, resolveGrammarWasmPath } from './languages.js';

export interface TreeSitterRuntime {
  languages: Record<CodeLanguage, TreeSitter.Language>;
  createParser(language: CodeLanguage): TreeSitter.Parser;
}

let runtimePromise: Promise<TreeSitterRuntime> | null = null;

export function getTreeSitterRuntime(): Promise<TreeSitterRuntime> {
  if (!runtimePromise) {
    runtimePromise = loadTreeSitterRuntime();
  }

  return runtimePromise;
}

async function loadTreeSitterRuntime(): Promise<TreeSitterRuntime> {
  await TreeSitter.Parser.init({
    locateFile: () => resolveCoreWasmPath(),
  });

  const languages: Record<CodeLanguage, TreeSitter.Language> = {
    javascript: await TreeSitter.Language.load(resolveGrammarWasmPath('javascript')),
    typescript: await TreeSitter.Language.load(resolveGrammarWasmPath('typescript')),
    python: await TreeSitter.Language.load(resolveGrammarWasmPath('python')),
    go: await TreeSitter.Language.load(resolveGrammarWasmPath('go')),
    java: await TreeSitter.Language.load(resolveGrammarWasmPath('java')),
  };

  return {
    languages,
    createParser(language: CodeLanguage): TreeSitter.Parser {
      const parser = new TreeSitter.Parser();
      parser.setLanguage(languages[language]);
      return parser;
    },
  };
}
