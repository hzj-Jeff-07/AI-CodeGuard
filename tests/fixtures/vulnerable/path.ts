// Vulnerable: Path Traversal (CG-030)
import fs from 'fs';
import path from 'path';

function readUserFile(filename: string) {
  const content = fs.readFileSync("/uploads/" + filename, 'utf-8');
  return content;
}

function streamFile(filePath: string) {
  return fs.createReadStream(`/data/${filePath}`);
}

// Vulnerable: Arbitrary File Access (CG-031)
import express from 'express';

function setupRoutes(app: express.Application) {
  app.get('/download', (req, res) => {
    const filePath = req.query.path as string;
    fs.readFile(filePath, (err, data) => {
      res.send(data);
    });
  });

  app.get('/view', (req, res) => {
    const content = fs.readFileSync(req.params.file, 'utf-8');
    res.send(content);
  });
}
