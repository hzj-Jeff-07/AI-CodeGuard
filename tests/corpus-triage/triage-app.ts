// Stage 2 triage corpus — every line that Stage 1 flags carries a ground-truth
// verdict: `codeguard-real CG-XXX` (a genuine vulnerability Stage 2 should
// CONFIRM) or `codeguard-fp CG-XXX` (a Stage 1 false positive Stage 2 should
// DISMISS). The triage harness fails if Stage 1 reports an unlabeled finding.

import express from 'express';
const app = express();

app.get('/user/:id', async (req: any, res: any) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`); // codeguard-real CG-001
  res.json(rows);
});

app.get('/go', (req: any, res: any) => {
  res.redirect(req.query.next); // codeguard-real CG-025
});

export function legacyEncrypt(key: Buffer, data: Buffer) {
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null); // codeguard-real CG-021
  return cipher.update(data);
}

export function calculatorDemo() {
  // eval of a hard-coded constant: code smell, but no injection surface.
  return eval('2 + 2'); // codeguard-fp CG-003
}

export function pollWithJitter(pollSession: () => void) {
  // Math.random for timing jitter; "session" nearby is why Stage 1 fires,
  // but nothing security-sensitive is derived from the value.
  const sessionJitterMs = Math.random() * 250; // codeguard-fp CG-022
  // setInterval with a function reference (not a code string) — the eval-family
  // rule fires on the name alone; nothing is evaluated.
  setInterval(pollSession, 5000 + sessionJitterMs); // codeguard-fp CG-003
}

export function notifyReset(userId: string) {
  // Mentions "password" but logs no secret value.
  console.log('password reset email queued for user', userId); // codeguard-fp CG-040
}
