// Vulnerable: Security Misconfiguration (CG-050)
import express from 'express';
import cors from 'cors';

const app = express();

// CORS wildcard
app.use(cors({ origin: '*' }));

// Cookie without secure flag
app.use((req, res, next) => {
  res.cookie('session', 'abc', { secure: false });
  res.cookie('token', 'xyz', { httpOnly: false });
  res.cookie('pref', 'dark', { sameSite: 'None' });
  next();
});

// Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
