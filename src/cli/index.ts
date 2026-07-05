import { Command } from 'commander';
import { createScanCommand } from './commands/scan.js';
import { createInitCommand } from './commands/init.js';
import { createRulesCommand } from './commands/rules.js';
import { VERSION } from '../version.js';

const program = new Command();

program
  .name('ai-codeguard')
  .description('AI-powered code security scanner')
  .version(VERSION);

program.addCommand(createScanCommand());
program.addCommand(createInitCommand());
program.addCommand(createRulesCommand());

program.parse();
