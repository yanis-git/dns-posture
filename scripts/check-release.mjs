import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
const tag = process.env.GITHUB_REF_NAME;
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(version) || tag !== `v${version}`) {
  throw new Error(`Tag ${tag} does not match package version ${version}`);
}
const tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n');
if (tracked.some((p) => /(^|\/)\.env(?:$|\.(?!example$))|\.zone$|\.csv$|^storage\/(?!.*\.gitkeep$)/.test(p))) {
  throw new Error('Operational data is tracked');
}
