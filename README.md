# ProofTask SDKs and offline verifier

The public source of ProofTask's client SDKs and offline verifier for ProofTask result records. Licensed under the
[Apache License, Version 2.0](LICENSE).

| Directory | Package | What it is |
| --- | --- | --- |
| [`typescript/`](typescript) | [`@prooftask/sdk`](https://www.npmjs.com/package/@prooftask/sdk) on npm | Agent API client for TypeScript and JavaScript, webhook signature verification, offline record verification with the published verifier |
| [`python/`](python) | [`prooftask`](https://pypi.org/project/prooftask/) on PyPI | Agent API client for Python and `prooftask.conformity`, an independent offline verifier for Conformity records |
| [`verifiers/`](verifiers) | — | `verify-conformity.mjs`, the offline verifier served at [prooftask.com/developers/verify-conformity.mjs](https://prooftask.com/developers/verify-conformity.mjs) (Node.js, no dependencies, no network) |

A result record states what was agreed, delivered and decided. The verifiers check its signatures and integrity
offline against issuer keys you obtain independently; they do not establish work quality, payment or company authority.

## Read-only, synced copy

This repository is a one-way copy of the SDK and verifier sources from ProofTask's main repository, refreshed after
each verified production release. Each commit is named after the source commit it was built from. Pull requests are
not merged here; changes made here are overwritten by the next sync.

## Documentation and specification

- Developer documentation: https://prooftask.com/developers
- Offline verification: https://prooftask.com/developers/offline-verification.md
- Conformity Record specification and conformance suite: https://github.com/cognitive-emergence/tsto-spec

## Building and testing

TypeScript (Node.js 22.13 or later):

```sh
cd typescript
npm install
npm run typecheck
npm pack        # builds dist/ and copies ../verifiers/verify-conformity.mjs into verifier/
```

Python (3.9 or later, standard library only):

```sh
cd python
python3 -I tests/test_sdk.py
python3 -I tests/test_conformity.py
```

## Reporting issues

Report problems and questions through ProofTask support: https://prooftask.com/support.
Report security vulnerabilities as described in https://prooftask.com/.well-known/security.txt.
