"""python -m prooftask.conformity [--sessions | --result-file] ARTIFACT TRUST [OPTIONS.json]

Prints the verification report as JSON. Exit status: 0 verified or partial disclosure (read the reasons),
1 INVALID, 3 INDETERMINATE, 2 usage error.
Use --sessions on a downloaded result record or full native Package for its private issuer-observed session timeline.
Use --result-file to also verify public registration with independent issuer keys.
OPTIONS.json may supply independent "anchorTrust" for a Package. A Status statement requires
"checkedAt" (canonical UTC) and "expectedStatus" {issuer, resultId, headDigest}. This is the verifier command contract of conformance/conformity-1.
"""
import json
import sys

from ._json import InputError, parse_bytes
from .verifier import inspect_record_sessions, inspect_result_file, verify_artifact

LIMIT = 17 * 1024 * 1024


def _read(path, limit):
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input too large: " + path)
    return data


def main(argv):
    readers = {"--sessions": inspect_record_sessions, "--result-file": inspect_result_file}
    reader = readers.get(argv[0]) if argv else None
    if reader:
        argv = argv[1:]
    if len(argv) not in (2, 3) or any(a.startswith("-") for a in argv):
        sys.stderr.write(__doc__)
        return 2
    try:
        artifact, trust = _read(argv[0], LIMIT), parse_bytes(_read(argv[1], 1024 * 1024), 1024 * 1024)
        options = parse_bytes(_read(argv[2], 256 * 1024)) if len(argv) == 3 else {}
    except (OSError, ValueError, InputError) as error:
        sys.stderr.write("Cannot read input: %s\n" % error)
        return 2
    if not isinstance(options, dict):
        sys.stderr.write("OPTIONS must be a JSON object\n")
        return 2
    if reader:
        try:
            details = reader(artifact, trust, anchor_trust=options.get("anchorTrust"))
        except ValueError as error:
            sys.stderr.write("Cannot inspect the signed delivery record: %s\n" % error)
            return 1
        sys.stdout.write(json.dumps(details, indent=2, ensure_ascii=False) + "\n")
        registration = details.get("registration", {})
        if registration.get("status") == "FAILED" or registration.get("treeHeadTime", {}).get("status") == "FAILED":
            return 1
        if details.get("registrationExpected") and registration.get("status") in {"PENDING", "NOT_PRESENT"}:
            return 3
        return 0
    report = verify_artifact(artifact, trust, checked_at=options.get("checkedAt"), expected_status=options.get("expectedStatus"),
                             anchor_trust=options.get("anchorTrust"))
    sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return {"INVALID": 1, "INDETERMINATE": 3}.get(report["status"], 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
