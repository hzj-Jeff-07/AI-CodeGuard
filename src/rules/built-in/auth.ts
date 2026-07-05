import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// `:=` covers Go short variable declarations; `[:=]` covers JS/TS/Python/Java
const CRED_PATTERNS = /(?:password|passwd|secret|api[_-]?key|token|credential|auth[_-]?token|private[_-]?key)\s*(?::=|[:=])\s*['"`](?![\s'"`${}])[^'"`]{3,}['"`]/i;

export const hardcodedCredentials: BuiltInRule = {
  id: 'CG-020',
  name: 'Hardcoded Credentials',
  severity: 'high',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects hardcoded passwords, API keys, and secrets in source code.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'assignment' && node.rawType !== 'hardcoded_credential') return null;

    if (CRED_PATTERNS.test(node.text)) {
      // Exclude common false positives
      const lower = node.text.toLowerCase();
      if (lower.includes('process.env') || lower.includes('os.environ') || lower.includes('placeholder')
        || lower.includes('example') || lower.includes('xxx') || lower.includes('changeme')) {
        return null;
      }

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-020',
        ruleName: 'Hardcoded Credentials',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 2),
        confidence: 0.7,
        metadata: {},
      };
    }

    return null;
  },
};

const WEAK_CRYPTO = ['md5', 'sha1', 'sha-1', 'des', 'rc4', 'md4'];
const CRYPTO_CALLS = ['createHash', 'createCipher', 'createCipheriv', 'createDecipher',
  'hashlib.md5', 'hashlib.sha1'];
// Go: the package itself is the weak-crypto signal (crypto/md5, crypto/sha1,
// crypto/des, crypto/rc4 have no strong-algorithm alternative under the same name).
const WEAK_CRYPTO_PACKAGES_GO = ['md5', 'sha1', 'des', 'rc4', 'md4'];
const CRYPTO_OBJECTS_JAVA = ['MessageDigest', 'Cipher'];

export const weakCryptography: BuiltInRule = {
  id: 'CG-021',
  name: 'Weak Cryptography',
  severity: 'medium',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  description: 'Detects use of weak cryptographic algorithms (MD5, SHA1, DES, RC4).',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    if (ctx.language === 'go') {
      if (!call.object || !WEAK_CRYPTO_PACKAGES_GO.includes(call.object)) return null;

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-021',
        ruleName: 'Weak Cryptography',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 2),
        confidence: 0.85,
        metadata: { package: call.object, method: call.name },
      };
    }

    if (ctx.language === 'java') {
      const isWeakCall = call.object !== null
        && CRYPTO_OBJECTS_JAVA.includes(call.object)
        && call.name === 'getInstance';
      if (!isWeakCall) return null;

      const usesWeakAlgo = WEAK_CRYPTO.some(algo =>
        call.fullExpression.toLowerCase().includes(`"${algo}"`)
      );
      if (!usesWeakAlgo) return null;

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-021',
        ruleName: 'Weak Cryptography',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 2),
        confidence: 0.85,
        metadata: { method: call.name, object: call.object },
      };
    }

    const isWeakCall = CRYPTO_CALLS.some(c => {
      const parts = c.split('.');
      if (parts.length === 2) {
        return call.object?.includes(parts[0]) && call.name === parts[1];
      }
      return call.name === c;
    });

    if (!isWeakCall) return null;

    const usesWeakAlgo = WEAK_CRYPTO.some(algo =>
      call.fullExpression.toLowerCase().includes(`'${algo}'`) ||
      call.fullExpression.toLowerCase().includes(`"${algo}"`)
    );

    if (!usesWeakAlgo) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-021',
      ruleName: 'Weak Cryptography',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.85,
      metadata: { method: call.name },
    };
  },
};
