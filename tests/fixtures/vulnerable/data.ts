// Vulnerable: Sensitive Data Exposure (CG-040)
function logUserInfo(user: any) {
  console.log("User login:", user.password);
  console.log("Credit card:", user.creditCard);
  console.log(`SSN: ${user.ssn}`);
}

// Vulnerable: Insecure Deserialization (CG-041)
import yaml from 'js-yaml';

function parseConfig(data: string) {
  return yaml.load(data);
}

function processPickle(data: Buffer) {
  // Python-style but in TS context
  // pickle.loads(data);
}
