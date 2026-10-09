#!/usr/bin/env node
import { main } from './ovh.mjs';
try {
  await main(process.argv.slice(2));
} catch (error) {
  console.error(`ERROR ${error.message}`);
  process.exitCode = 1;
}
