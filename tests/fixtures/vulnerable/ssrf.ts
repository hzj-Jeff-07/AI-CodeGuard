// Vulnerable: SSRF (CG-060)
import axios from 'axios';

async function fetchUrl(url: string) {
  return axios.get(url);
}

async function proxyRequest(req: any) {
  const target = req.query.url;
  const response = await fetch(target);
  return response.json();
}

async function callWebhook(endpoint: string) {
  return fetch(`http://internal-api/${endpoint}`);
}
