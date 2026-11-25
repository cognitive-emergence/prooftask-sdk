// Prepares the package contents (npm runs this before pack and publish): compiles src/ to dist/ and copies the
// published offline verifier byte for byte from the repository's generated bundle (scripts/verify-conformity.mjs,
// built by scripts/build-conformity-verifier.mjs). Run from a checkout of either repository: the public
// cognitive-emergence/prooftask-sdk keeps that file at verifiers/verify-conformity.mjs.
import { copyFileSync, existsSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = fileURLToPath(new URL('../', import.meta.url));
const source = ['../../verifiers/verify-conformity.mjs', '../../../scripts/verify-conformity.mjs']
  .map(candidate => fileURLToPath(new URL(candidate, import.meta.url))).find(path => existsSync(path));
if (!source) throw new Error('verify-conformity.mjs not found: expected ../verifiers/ (public SDK repository) or ../../scripts/ (ProofTask repository)');
const tsc = process.env.TSC ?? join(dirname(createRequire(here + 'package.json').resolve('typescript/package.json')), 'bin', 'tsc');
rmSync(here + 'dist', { recursive: true, force: true });
execFileSync(process.execPath, [tsc, '-p', here + 'tsconfig.build.json'], { stdio: 'inherit' });
mkdirSync(here + 'verifier', { recursive: true });
copyFileSync(source, here + 'verifier/verify-conformity.mjs');
console.log('verifier/verify-conformity.mjs sha256 ' + createHash('sha256').update(readFileSync(here + 'verifier/verify-conformity.mjs')).digest('hex'));
