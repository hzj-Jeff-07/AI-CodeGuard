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
// PHP's md5()/sha1() are bare global functions with no algorithm argument —
// calling them at all is the weak-crypto signal, unlike hash(), which takes
// the algorithm as its first argument and needs the WEAK_CRYPTO text check.
const WEAK_CRYPTO_BARE_PHP = ['md5', 'sha1'];

export const weakCryptography: BuiltInRule = {
  id: 'CG-021',
  name: 'Weak Cryptography',
  severity: 'medium',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
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

    if (ctx.language === 'php') {
      const isWeakBareCall = call.object === null && WEAK_CRYPTO_BARE_PHP.includes(call.name);
      const isWeakHashCall = call.object === null && call.name === 'hash'
        && WEAK_CRYPTO.some(algo =>
          call.fullExpression.toLowerCase().includes(`'${algo}'`) ||
          call.fullExpression.toLowerCase().includes(`"${algo}"`)
        );
      if (!isWeakBareCall && !isWeakHashCall) return null;

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

// A non-cryptographic PRNG (Math.random, Python's random module, Go's
// math/rand, java.util.Random, PHP's rand()/mt_rand()) is fine for sampling,
// jitter, or UI — the problem is only when its output is used as a security
// token, session ID, password, or similar. Since Stage 1 has no dataflow
// analysis, that intent is inferred from security-sensitive keywords in the
// surrounding lines rather than tracing where the value actually flows.
// Deliberately no `\b` word-boundary anchors: the keyword is typically
// embedded in a camelCase/PascalCase identifier (`generateSessionID`,
// `passwordResetToken`), where a boundary never appears between the words.
const INSECURE_RANDOM_CONTEXT = /token|session|password|passwd|secret|otp|api[_-]?key|reset|nonce|csrf/i;
// math/rand's Intn/Int31/Int63/Float32/Float64/Perm/Shuffle have no
// crypto/rand equivalent under the same name (crypto/rand only exposes
// Read/Int/Prime), so matching these names alone is unambiguous.
const INSECURE_RAND_FNS_GO = ['Intn', 'Int31', 'Int31n', 'Int63', 'Int63n',
  'Float32', 'Float64', 'Perm', 'Shuffle'];
// Python's `secrets` module is the secure alternative; `random`'s functions
// are the insecure signal.
const INSECURE_RAND_FNS_PY = ['random', 'randint', 'randrange', 'choice', 'sample', 'uniform'];
const INSECURE_RAND_FNS_PHP = ['rand', 'mt_rand'];

export const insecureRandomness: BuiltInRule = {
  id: 'CG-022',
  name: 'Insecure Randomness',
  severity: 'medium',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects a non-cryptographic random number generator used in a security-sensitive context (tokens, sessions, passwords).',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    let isInsecureRandomCall: boolean;
    if (ctx.language === 'go') {
      isInsecureRandomCall = call.object === 'rand' && INSECURE_RAND_FNS_GO.includes(call.name);
    } else if (ctx.language === 'java') {
      // `new Random(...)`; `new SecureRandom(...)` has a different name and
      // is intentionally not matched.
      isInsecureRandomCall = call.object === null && call.name === 'Random';
    } else if (ctx.language === 'php') {
      isInsecureRandomCall = call.object === null && INSECURE_RAND_FNS_PHP.includes(call.name);
    } else if (ctx.language === 'python') {
      isInsecureRandomCall = call.object === 'random' && INSECURE_RAND_FNS_PY.includes(call.name);
    } else {
      isInsecureRandomCall = call.object === 'Math' && call.name === 'random';
    }
    if (!isInsecureRandomCall) return null;

    if (!INSECURE_RANDOM_CONTEXT.test(ctx.getContext(node, 3))) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-022',
      ruleName: 'Insecure Randomness',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.65,
      metadata: { method: call.name },
    };
  },
};
