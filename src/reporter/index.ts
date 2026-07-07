import { writeFile } from 'node:fs/promises';
import type { ScanResult, OutputFormat } from '../types/index.js';
import { formatText } from './text.js';
import { formatJSON } from './json.js';
import { formatSARIF } from './sarif.js';
import { formatGitHubReview } from './github.js';

export async function generateReport(
  result: ScanResult,
  format: OutputFormat,
  outputFile?: string,
): Promise<string> {
  let content: string;

  switch (format) {
    case 'text':
      content = formatText(result);
      break;
    case 'json':
      content = formatJSON(result);
      break;
    case 'sarif':
      content = formatSARIF(result);
      break;
    case 'github':
      content = formatGitHubReview(result);
      break;
  }

  if (outputFile) {
    await writeFile(outputFile, content, 'utf-8');
  }

  return content;
}

export { formatText } from './text.js';
export { formatJSON } from './json.js';
export { formatSARIF } from './sarif.js';
export { formatGitHubReview } from './github.js';
