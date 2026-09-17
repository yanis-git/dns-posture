// Runtime paths and credential loading.
//
// Everything the tool writes lives under a single storage directory, resolved
// once here so tests (and anyone who wants their data elsewhere) can relocate
// it with OVH_STORAGE_DIR instead of patching the code.

import { existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

export const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Load the credentials file if there is one.
 *
 * A missing file is not an error: credentials may come from the real
 * environment (CI, direnv, a secret manager), and `--help` must work on a fresh
 * clone that has no .env at all. OVH_ENV_FILE points somewhere else — useful to
 * keep one file per OVH account, and to guarantee that tests never pick up the
 * operator's real credentials.
 */
export function loadEnv(root = ROOT) {
  const path = process.env.OVH_ENV_FILE
    ? resolve(process.env.OVH_ENV_FILE)
    : join(root, '.env');
  if (existsSync(path)) process.loadEnvFile(path);
  return path;
}

/**
 * Resolve the policy file — the check/remedy configuration, not this module.
 *
 * OVH_POLICY_FILE relocates it, on the model of OVH_ENV_FILE: one policy per
 * client, or a policy kept outside a publishable repository because its
 * `domains:` section names real domains and their exceptions.
 *
 * SECURITY: the policy file is a JavaScript module, and loading it EXECUTES it.
 * Point OVH_POLICY_FILE only at a file you would run.
 */
export function policyFile(root = ROOT) {
  const custom = process.env.OVH_POLICY_FILE;
  return custom ? resolve(custom) : join(root, 'config', 'policy.mjs');
}

/** Resolve the storage directory. OVH_STORAGE_DIR wins when set. */
export function storageDir(root = ROOT) {
  const custom = process.env.OVH_STORAGE_DIR;
  return custom ? resolve(custom) : join(root, 'storage');
}

export function paths(root = ROOT) {
  const storage = storageDir(root);
  return {
    storage,
    backups: join(storage, 'backups'),
    reports: join(storage, 'reports'),
    inventoryMd: join(storage, 'inventory.md'),
    inventoryJson: join(storage, 'inventory.json'),
    // inventory.* and compliance.* are the two portfolio-wide states, both at
    // the root of storage/. reports/ stays reserved for per-run artefacts.
    complianceMd: join(storage, 'compliance.md'),
    complianceJson: join(storage, 'compliance.json'),
    complianceCsv: join(storage, 'compliance.csv'),
  };
}

/** Create the storage tree if it does not exist yet. */
export function ensureStorage(root = ROOT) {
  const p = paths(root);
  mkdirSync(p.backups, { recursive: true });
  mkdirSync(p.reports, { recursive: true });
  return p;
}

export const CREDENTIAL_VARS = ['APP_KEY', 'APP_SECRET'];

/**
 * Fail early, and by name, when credentials are missing. Without this the
 * first API call returns an opaque OVH 400 halfway through a run.
 */
export function requireCredentials(env = process.env) {
  const missing = CREDENTIAL_VARS.filter((k) => !env[k]);
  if (missing.length) {
    throw new Error(
      `Missing OVH credentials: ${missing.join(', ')}.\n`
      + '   Copy .env.example to .env and fill it in — see the "Getting started"\n'
      + '   section of the README to create an OVH application.',
    );
  }
}
