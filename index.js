#!/usr/bin/env node

import Orchestrator from './src/core/Orchestrator.js';

const url = process.argv[2];

if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
  console.error('\nError: Provide a valid URL as the first argument.');
  console.error('Usage: node index.js <URL>\n');
  console.error('Example: node index.js https://myapp.example.com\n');
  process.exit(1);
}

const rootDir = process.cwd();

process.on('unhandledRejection', (err) => {
  console.error('Unhandled error:', err?.message || err);
  process.exit(1);
});

const orchestrator = new Orchestrator(url, rootDir);
orchestrator.run().catch((err) => {
  console.error('Fatal error:', err?.message || err);
  process.exit(1);
});
