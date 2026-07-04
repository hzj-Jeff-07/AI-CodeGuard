import { Command } from 'commander';
import { createScanCommand } from './commands/scan.js';
import { createInitCommand } from './commands/init.js';
import { createRulesCommand } from './commands/rules.js';

const program = new Command();

program
  .name('ai-codeguard')
  .description('AI-powered code security scanner')
  .version('0.2.0');

program.addCommand(createScanCommand());
program.addCommand(createInitCommand());
program.addCommand(createRulesCommand());

program.parse();
