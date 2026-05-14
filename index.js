#!/usr/bin/env node

import path from 'path';
import fs from 'fs';
import Orchestrator from './src/core/Orchestrator.js';

const url     = process.argv[2];
const pathArg = process.argv[3];

if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
  console.error('\nError: URL inválida o no proporcionada.');
  console.error('Uso:    node index.js <URL> [path-al-codigo]');
  console.error('');
  console.error('  <URL>            URL de la aplicación objetivo (obligatorio)');
  console.error('  [path-al-codigo] Ruta al código fuente a analizar (opcional, default: directorio actual)');
  console.error('');
  console.error('Ejemplos:');
  console.error('  node index.js https://myapp.com');
  console.error('  node index.js http://localhost:3001 ./test-mockup');
  console.error('  node index.js http://localhost:3001 /ruta/absoluta/al/proyecto\n');
  process.exit(1);
}

// Resolver rootDir: argumento explícito o cwd como fallback
let rootDir;
if (pathArg) {
  rootDir = path.resolve(pathArg);
  if (!fs.existsSync(rootDir)) {
    console.error(`\nError: El path proporcionado no existe: ${rootDir}\n`);
    process.exit(1);
  }
  if (!fs.statSync(rootDir).isDirectory()) {
    console.error(`\nError: El path proporcionado no es un directorio: ${rootDir}\n`);
    process.exit(1);
  }
} else {
  rootDir = process.cwd();
}

process.on('unhandledRejection', (err) => {
  console.error('Error no manejado:', err?.message || err);
  process.exit(1);
});

const orchestrator = new Orchestrator(url, rootDir);
orchestrator.run().catch((err) => {
  console.error('Error fatal:', err?.message || err);
  process.exit(1);
});
