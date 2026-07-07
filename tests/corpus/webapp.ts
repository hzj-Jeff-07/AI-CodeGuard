// Labeled precision corpus — realistic Express-style handlers.
// Ground truth is annotated with trailing `codeguard-expect CG-XXX` comments;
// unannotated code is asserted clean. See tests/precision/precision.test.ts.

import express from 'express';
const app = express();

app.get('/user/:id', async (req: any, res: any) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`); // codeguard-expect CG-001
  res.json(rows);
});

app.get('/user-safe/:id', async (req: any, res: any) => {
  // Parameterized — safe.
  const rows = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(rows);
});

app.get('/go', (req: any, res: any) => {
  res.redirect(req.query.next); // codeguard-expect CG-025
});

app.get('/home', (_req: any, res: any) => {
  // Fixed target — safe.
  res.redirect('/dashboard');
});

app.post('/login', (req: any, res: any) => {
  const payload = jwt.verify(req.body.token, SECRET, { algorithms: ['none'] }); // codeguard-expect CG-026
  res.json(payload);
});

app.get('/download', (req: any, res: any) => {
  fs.readFile('./uploads/' + req.query.name, (e: any, d: any) => res.send(d)); // codeguard-expect CG-030 CG-031
});

app.get('/report', async (req: any, res: any) => {
  // Two-step build: the dynamic string is assembled first, then passed by
  // variable. Stage 1 has no dataflow, so this is a known miss (honest FN).
  const q = `SELECT * FROM reports WHERE owner = ${req.query.owner}`;
  const rows = await db.query(q); // codeguard-expect CG-001
  res.json(rows);
});
