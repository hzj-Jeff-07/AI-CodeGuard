import type { ASTNode, CallInfo, Language, SuspiciousNode } from '../../types/index.js';
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
  // `hashlib.md5(...)`/`hashlib.sha1(...)` are the direct forms; `hashlib.new('md5', ...)`
  // is the generic constructor and is caught via the weak-algorithm string.
  'hashlib.md5', 'hashlib.sha1', 'hashlib.new'];
// Go: the package itself is the weak-crypto signal (crypto/md5, crypto/sha1,
// crypto/des, crypto/rc4 have no strong-algorithm alternative under the same name).
const WEAK_CRYPTO_PACKAGES_GO = ['md5', 'sha1', 'des', 'rc4', 'md4'];
const CRYPTO_OBJECTS_JAVA = ['MessageDigest', 'Cipher'];
// PHP's md5()/sha1() are bare global functions with no algorithm argument —
// calling them at all is the weak-crypto signal, unlike hash(), which takes
// the algorithm as its first argument and needs the WEAK_CRYPTO text check.
const WEAK_CRYPTO_BARE_PHP = ['md5', 'sha1'];

function usesWeakAlgo(call: CallInfo): boolean {
  return WEAK_CRYPTO.some(algo =>
    call.fullExpression.toLowerCase().includes(`'${algo}'`) ||
    call.fullExpression.toLowerCase().includes(`"${algo}"`)
  );
}

// ECB is a weak block-cipher mode regardless of the underlying algorithm:
// identical plaintext blocks encrypt to identical ciphertext, leaking
// structure (the classic "ECB penguin"). The mode token shows up the same way
// across ecosystems — `aes-256-ecb` (Node/PHP algorithm strings), `AES/ECB/...`
// (Java transformation), `MODE_ECB` (pycryptodome) — so one language-agnostic
// check covers them all. Gated to actual cipher calls so an incidental "ecb"
// elsewhere can't trip it.
const ECB_MODE = /(?:MODE_ECB|[/-]ecb)\b/i;
const CIPHER_CALLS = new Set([
  'createcipheriv', 'createdecipheriv', 'createcipher', 'createdecipher', // Node
  'getinstance',                                                          // Java Cipher
  'new',                                                                  // pycryptodome AES.new/DES.new
  'openssl_encrypt', 'openssl_decrypt', 'mcrypt_encrypt', 'mcrypt_decrypt', // PHP
]);

function usesEcbMode(call: CallInfo): boolean {
  return CIPHER_CALLS.has(call.name.toLowerCase()) && ECB_MODE.test(call.fullExpression);
}

// Node's `createCipher`/`createDecipher` (no `iv`) are deprecated: they derive
// the key/IV from the password with a single unsalted MD5, so their use is a
// weakness on its own, independent of the algorithm. The `iv` variants
// (`createCipheriv`/`createDecipheriv`) are the secure replacement and are
// matched by exact name, not substring.
function usesDeprecatedCipher(call: CallInfo): boolean {
  return call.name === 'createCipher' || call.name === 'createDecipher';
}

// Each language's weak-crypto-call matcher, keyed by language so adding a new
// one is a single map entry instead of another branch in an if/else chain.
// `javascript`/`typescript`/`python` share the default (no entry needed).
const WEAK_CRYPTO_MATCHERS: Partial<Record<Language, (call: CallInfo) => boolean>> = {
  go: call => call.object !== null && WEAK_CRYPTO_PACKAGES_GO.includes(call.object),
  java: call => call.object !== null && CRYPTO_OBJECTS_JAVA.includes(call.object)
    && call.name === 'getInstance' && usesWeakAlgo(call),
  php: call => (call.object === null && WEAK_CRYPTO_BARE_PHP.includes(call.name))
    || (call.object === null && call.name === 'hash' && usesWeakAlgo(call)),
};
const DEFAULT_WEAK_CRYPTO_MATCHER = (call: CallInfo): boolean => {
  const isWeakCall = CRYPTO_CALLS.some(c => {
    const parts = c.split('.');
    if (parts.length === 2) {
      return call.object?.includes(parts[0]) && call.name === parts[1];
    }
    return call.name === c;
  });
  return isWeakCall && usesWeakAlgo(call);
};

export const weakCryptography: BuiltInRule = {
  id: 'CG-021',
  name: 'Weak Cryptography',
  severity: 'medium',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects use of weak cryptographic algorithms (MD5, SHA1, DES, RC4) or the insecure ECB block-cipher mode.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const matcher = WEAK_CRYPTO_MATCHERS[ctx.language] ?? DEFAULT_WEAK_CRYPTO_MATCHER;
    // A weak algorithm (per-language matcher), the ECB mode, or Node's
    // deprecated password-based cipher (both language-agnostic) is enough to flag.
    if (!matcher(call) && !usesEcbMode(call) && !usesDeprecatedCipher(call)) return null;

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
      // Go's metadata key is `package` (its receiver is the crypto package
      // itself, e.g. `md5`), everyone else's is `object`.
      metadata: ctx.language === 'go' ? { package: call.object, method: call.name }
        : call.object !== null ? { method: call.name, object: call.object }
        : { method: call.name },
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

const INSECURE_RANDOM_MATCHERS: Partial<Record<Language, (call: CallInfo) => boolean>> = {
  go: call => call.object === 'rand' && INSECURE_RAND_FNS_GO.includes(call.name),
  // `new Random(...)`; `new SecureRandom(...)` has a different name and is
  // intentionally not matched.
  java: call => call.object === null && call.name === 'Random',
  php: call => call.object === null && INSECURE_RAND_FNS_PHP.includes(call.name),
  python: call => call.object === 'random' && INSECURE_RAND_FNS_PY.includes(call.name),
};
const DEFAULT_INSECURE_RANDOM_MATCHER = (call: CallInfo): boolean =>
  call.object === 'Math' && call.name === 'random';

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

    const matcher = INSECURE_RANDOM_MATCHERS[ctx.language] ?? DEFAULT_INSECURE_RANDOM_MATCHER;
    if (!matcher(call)) return null;

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
