/** Offline record verification by the published ProofTask verifier (verify-conformity.mjs, the file served at
 * /developers/verify-conformity.mjs). This module does not reimplement verification: it runs that exact verifier in a
 * child Node process that may read only the verifier and a private temporary directory holding your files.
 * Nothing is sent over the network. Verdicts are VERIFIED_WITH_LIMITATIONS, PARTIAL_DISCLOSURE, INDETERMINATE or INVALID;
 * read the report's reasons, which name what the check did not prove. */
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OfflineVerificationError } from './errors.ts';

type Input = string | Uint8Array | Record<string, unknown>;

export interface OfflineVerificationInput {
  /** The stored result record file (prooftask-result-record-<id>.json) or a Conformity Package, as bytes, text or parsed JSON. */
  record: Input;
  /** Issuer keys you trust: a ProofTask trust bundle (for example the copy in a continuity mirror) or a Conformity issuer policy.
   * Without it, the record's own keys are used only when they match the ProofTask keys pinned in the verifier. */
  trust?: Input;
  /** Check as of this canonical UTC time (default now), for example 2026-11-21T00:00:00.000Z. */
  checkedAt?: string;
  /** Saved signed status statement (--status=). */
  status?: Input;
  /** Previously saved copy to compare with (--previous=). */
  previous?: Input;
  /** Independently approved party keys (--participants=). */
  participants?: Input;
  /** Signed agreement files (--agreement-proofs=). */
  agreementProofs?: Input;
  /** Independently approved company authority policy (--authority=). */
  authority?: Input;
  /** Path of verify-conformity.mjs. Defaults to the copy shipped with this package. */
  verifierPath?: string;
  timeoutMs?: number;
}

export interface OfflineVerificationResult {
  /** VERIFIED_WITH_LIMITATIONS, PARTIAL_DISCLOSURE, INDETERMINATE or INVALID. */
  outcome: string;
  /** The verifier's exit status: 0 verified (read the limits), 1 INVALID, 3 cannot determine. */
  exitCode: number;
  /** The verifier's full JSON report. */
  report: Record<string, unknown>;
}

/** The verifier shipped in the package (verifier/), or the repository's generated bundle when running from a checkout. */
export function defaultVerifierPath(): string {
  for (const candidate of ['../verifier/verify-conformity.mjs', '../../../scripts/verify-conformity.mjs']) {
    const path = fileURLToPath(new URL(candidate, import.meta.url));
    if (existsSync(path)) return realpathSync(path);
  }
  throw new OfflineVerificationError('verify-conformity.mjs not found; pass verifierPath', null, '');
}

const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const encode = (value: Input) => typeof value === 'string' ? Buffer.from(value, 'utf8') : value instanceof Uint8Array ? value : Buffer.from(JSON.stringify(value), 'utf8');

export async function verifyRecordOffline(input: OfflineVerificationInput): Promise<OfflineVerificationResult> {
  if (input.checkedAt !== undefined && !UTC_TIME.test(input.checkedAt)) throw new TypeError('checkedAt must be a canonical UTC time such as 2026-11-21T00:00:00.000Z');
  const verifier = input.verifierPath ? realpathSync(input.verifierPath) : defaultVerifierPath();
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'prooftask-verify-'));
  try {
    const file = (name: string, value: Input) => { const path = join(directory, name); writeFileSync(path, encode(value), { mode: 0o600 }); return path; };
    const args = [file('record.json', input.record)];
    if (input.trust !== undefined) args.push(file('trust.json', input.trust));
    if (input.checkedAt) args.push('--at=' + input.checkedAt);
    for (const [key, flag] of [['status', '--status='], ['previous', '--previous='], ['participants', '--participants='], ['agreementProofs', '--agreement-proofs='], ['authority', '--authority=']] as const) {
      const value = input[key]; if (value !== undefined) args.push(flag + file(key + '.json', value));
    }
    const { code, stdout, stderr } = await new Promise<{ code: number | null; stdout: string; stderr: string }>(resolve => {
      execFile(process.execPath, ['--permission', '--allow-fs-read=' + directory, '--allow-fs-read=' + verifier, verifier, ...args],
        { cwd: directory, env: {}, timeout: input.timeoutMs ?? 60000, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8' },
        (error, stdout, stderr) => resolve({ code: error ? (typeof error.code === 'number' ? error.code : null) : 0, stdout, stderr }));
    });
    if (code !== 0 && code !== 1 && code !== 3) throw new OfflineVerificationError('The offline verifier could not run (exit ' + code + ')', code, stderr);
    const text = stdout.trim() || stderr.trim();
    let report: Record<string, unknown>;
    try { report = JSON.parse(text) as Record<string, unknown>; } catch { throw new OfflineVerificationError('The offline verifier returned no JSON report', code, stderr); }
    const outcome = typeof report.outcome === 'string' ? report.outcome : typeof report.status === 'string' ? report.status : code === 1 ? 'INVALID' : 'INDETERMINATE';
    return { outcome, exitCode: code, report };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}
