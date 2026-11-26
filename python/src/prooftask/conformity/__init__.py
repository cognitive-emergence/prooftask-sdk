"""Independent offline verifier for Conformity records, packages and their timestamp evidence.

    from prooftask.conformity import verify_record
    report = verify_record(open("record.json", "rb").read(), trust)

See docs/developers/CONFORMITY_VERIFIER.md (served at /developers/conformity-verifier.md) and `python -m prooftask.conformity --help`.
"""
from .verifier import UnsupportedEvidence, inspect_record_sessions, inspect_result_file, verify_artifact, verify_record

__all__ = ["verify_record", "verify_artifact", "UnsupportedEvidence", "inspect_record_sessions", "inspect_result_file"]
