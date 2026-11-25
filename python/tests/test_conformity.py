"""Unit tests for the independent Conformity verifier: RFC 8032 Ed25519 vectors, RFC 8785 serialization,
strict JSON input and the vendored standard files. The full behaviour is checked by the language-neutral suite in
conformance/conformity-1 (tests/conformity-conformance-suite.test.ts runs it). Standard library only."""
import base64
import hashlib
import json
import os
import sys
import unittest

PACKAGE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PACKAGE, "src"))
# In the ProofTask repository (sdk/python) the vendored standard files and the conformance suite sit beside the SDK.
# The public SDK repository holds the SDK only; the specification and suite are in cognitive-emergence/tsto-spec.
ROOT = os.path.abspath(os.path.join(PACKAGE, "..", ".."))
IN_PROOFTASK_REPOSITORY = os.path.basename(os.path.dirname(PACKAGE)) == "sdk"
NEEDS_SPECIFICATION = unittest.skipUnless(IN_PROOFTASK_REPOSITORY, "needs the specification files (cognitive-emergence/tsto-spec)")

from prooftask.conformity import _ed25519, verify_record  # noqa: E402
from prooftask.conformity._json import InputError, canonical, es_number, parse_bytes  # noqa: E402

# RFC 8032 section 7.1 (Ed25519): public key, message, signature.
RFC8032 = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vectors_verify(self):
        for public, message, signature in RFC8032:
            self.assertTrue(_ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))

    def test_rejections(self):
        public, message, signature = (bytes.fromhex(x) for x in RFC8032[2])
        self.assertFalse(_ed25519.verify(public, message + b"\0", signature))
        flipped = bytearray(signature)
        flipped[0] ^= 1
        self.assertFalse(_ed25519.verify(public, message, bytes(flipped)))
        # S + L is the same group element but non-canonical: must be rejected (malleability).
        s = int.from_bytes(signature[32:], "little") + _ed25519.L
        self.assertFalse(_ed25519.verify(public, message, signature[:32] + s.to_bytes(32, "little")))
        self.assertFalse(_ed25519.verify(public[:31], message, signature))
        self.assertFalse(_ed25519.verify(b"\xff" * 32, message, signature))  # y >= p does not decode

    def test_spki_pem(self):
        pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEARWRAllaiVEYPt0ygb2eYbQy6l7Pn8xFy0JoeZE68e2o=\n-----END PUBLIC KEY-----\n"
        self.assertEqual(len(_ed25519.public_key_from_pem(pem)), 32)
        p256 = ("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiIVLUh2uhBQHmFqf3pWzSHSOg3jHHHhDQiUWkhMRxj0V"
                "\nE+OkAvBKAwBlGbqXYkqqgDqIGI5Ku9n4ib34sgHqnA==\n-----END PUBLIC KEY-----\n")
        self.assertIsNone(_ed25519.public_key_from_pem(p256))


class CanonicalJsonTest(unittest.TestCase):
    def test_rfc8785_numbers(self):
        # RFC 8785 appendix B and ECMAScript Number::toString boundaries.
        cases = {0.0: "0", -0.0: "0", 1e21: "1e+21", 1e20: "100000000000000000000", 1e-6: "0.000001", 1e-7: "1e-7",
                 9007199254740992.0: "9007199254740992", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
                 333333333.33333329: "333333333.3333333", 4.5: "4.5", 2e-3: "0.002", 0.000001234: "0.000001234"}
        for value, text in cases.items():
            self.assertEqual(es_number(value), text)

    def test_key_order_is_utf16(self):
        value = parse_bytes('{"\\u20ac":1,"\\ud83d\\ude00":2,"\\ufb33":3,"a":4,"\\u0080":5}'.encode())
        self.assertEqual(canonical(value), '{"a":4,"\u0080":5,"€":1,"\U0001f600":2,"דּ":3}')

    def test_strings_escape_like_json_stringify(self):
        self.assertEqual(canonical([" \"\\\n\x1f"]), '[" \\"\\\\\\n\\u001f"]')

    def test_strict_input(self):
        for text, code in [('{"a":1,"\\u0061":2}', "DUPLICATE_KEY"), ('{"a":NaN}', "NON_FINITE_NUMBER"), ("[1e400]", "NON_FINITE_NUMBER"),
                           ('["\\ud800"]', "INVALID_UNICODE"), ("[1] x", "INVALID_JSON"), ("﻿[]", "INVALID_JSON"), ("[01]", "INVALID_JSON"),
                           ("[" * 70 + "]" * 70, "LIMIT_EXCEEDED")]:
            with self.assertRaises(InputError) as caught:
                parse_bytes(text.encode("utf-8"))
            self.assertEqual(caught.exception.code, code, text)
        with self.assertRaises(InputError) as caught:
            parse_bytes(b'["\xff"]')
        self.assertEqual(caught.exception.code, "INVALID_UTF8")


class VendoredStandardsTest(unittest.TestCase):
    @NEEDS_SPECIFICATION
    def test_bundled_files_are_the_published_bytes(self):
        data = os.path.join(PACKAGE, "src", "prooftask", "conformity", "data")
        for name in sorted(os.listdir(data)):
            with open(os.path.join(data, name), "rb") as bundled, open(os.path.join(ROOT, "standards", name), "rb") as published:
                self.assertEqual(hashlib.sha256(bundled.read()).hexdigest(), hashlib.sha256(published.read()).hexdigest(), name)



@NEEDS_SPECIFICATION
class IndependentAnchorTest(unittest.TestCase):
    @staticmethod
    def fixture(path):
        with open(os.path.join(ROOT, "tests", "fixtures", path), encoding="utf-8") as handle:
            return json.load(handle)

    def test_real_sectigo_signature_chain_policy_and_imprint(self):
        from prooftask.conformity._anchor_policy import DEFAULT_TRUST
        from prooftask.conformity._timestamp import timestamp
        fixture = self.fixture("time-anchor/sectigo-2026-11-12.json")
        token = base64.b64decode(fixture["token"])
        roots = DEFAULT_TRUST["timeStampRoots"]
        validation = fixture["rootsAndCrlsPem"].encode()
        result = timestamp(token, fixture["digest"], roots, validation)
        self.assertEqual(result["genTime"], fixture["genTime"])
        self.assertEqual(result["tsa"], "Sectigo Public Time Stamping Signer R37")
        self.assertEqual(result["revocation"], "NOT_CHECKED")  # CRLs precede the required post-token observation.
        for wrong_token, imprint, pins in [(token, "00" * 32, roots), (token, fixture["digest"], []),
                                           (token[:-1] + bytes([token[-1] ^ 1]), fixture["digest"], roots)]:
            with self.assertRaises(ValueError):
                timestamp(wrong_token, imprint, pins, validation)
        with self.assertRaisesRegex(ValueError, "TRUST_TIME_POLICY_MISMATCH"):
            timestamp(token, fixture["digest"], roots, validation, ["1.2.3"])

    def test_frozen_root_pin_does_not_trust_siblings_in_multi_pem(self):
        from prooftask.conformity._anchor_policy import DEFAULT_TRUST
        from prooftask.conformity._anchors import restricted_tsa
        from prooftask.conformity._timestamp import pem_blocks
        root = DEFAULT_TRUST["timeStampRoots"][0]
        # One recipient-provided PEM may contain multiple certificates. The record freezes individual DER fingerprints.
        fixture = self.fixture("time-anchor/sectigo-2026-11-12.json")
        from prooftask.conformity._timestamp import single
        token = base64.b64decode(fixture["token"])
        carried = single(single(token).fields()[1].content).fields()[3].fields()[0].raw
        roots = [{"pem": root["pem"] + "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(carried).decode() + "-----END CERTIFICATE-----\n"}]
        policy = {"time": {"rootSha256": [root["sha256"]], "requirement": "OPTIONAL"}}
        record = {"specification": {"extensions": {"com.prooftask.agreement": {"trustPolicy": policy}}}}
        selected, _ = restricted_tsa({"timeStampRoots": roots}, record)
        only = list(pem_blocks(selected[0]["pem"].encode(), b"CERTIFICATE"))
        self.assertEqual([hashlib.sha256(der).hexdigest() for der in only], [root["sha256"]])
        self.assertEqual(len(selected), 1)

    def test_real_mainnet_proof_headers_and_checkpoint(self):
        from prooftask.conformity._anchor_policy import DEFAULT_TRUST
        from prooftask.conformity._bitcoin import MAGIC, verify_bitcoin
        fixture = self.fixture("bitcoin/mainnet-975744.json")
        leaf = bytes.fromhex(fixture["attested"]["coinbaseTxid"])[::-1]
        operations = b"".join(b"\xf0\x20" + bytes.fromhex(sibling)[::-1] + b"\x08\x08" for sibling in fixture["attested"]["merkle"])
        proof = MAGIC + leaf + operations + bytes.fromhex("000588960d73d719010381c73b")
        headers = b"".join(bytes.fromhex(h["headerHex"]) for h in fixture["headers"])
        params = DEFAULT_TRUST["bitcoin"]
        report, reason, upper = verify_bitcoin(proof, leaf.hex(), params, headers, 975744)
        self.assertEqual((report["status"], report["height"], report["confirmations"]), ("VERIFIED", 975745, 7))
        self.assertEqual(report["blockHash"], fixture["headers"][1]["hash"])
        self.assertEqual(reason, "BITCOIN_POW_LINKED_NOT_FULL_NODE")
        self.assertGreater(upper, report["blockTime"])
        self.assertEqual(verify_bitcoin(proof, leaf.hex(), params, headers[:240], 975744)[0]["status"], "PENDING")
        self.assertEqual(verify_bitcoin(proof, leaf.hex(), params, headers[80:], 975745)[1], "BITCOIN_CHECKPOINT_NOT_HELD")
        with self.assertRaises(ValueError):
            verify_bitcoin(proof, "00" * 32, params, headers, 975744)
        with self.assertRaises(ValueError):
            verify_bitcoin(proof, leaf.hex(), params, headers[:-1] + bytes([headers[-1] ^ 1]), 975744)

    def test_typed_index_requires_subject_and_bounded_items(self):
        from prooftask.conformity._anchors import TYPED, validate_index
        digest = "00" * 32
        item = {"type": "rfc3161", "token": "evidence/rfc3161/1.der", "assurance": "BEST_EFFORT",
                "subject": {"kind": "RECORD", "digest": digest}}
        index = {"schema": TYPED, "subject": {"alg": "sha-256", "digest": digest}, "items": [item]}
        self.assertIn(item["token"], validate_index(json.dumps(index).encode())[1])
        for change in [{"assurance": "UNKNOWN"}, {"token": "evidence/rfc3161/../1.der"}, {"subject": {"kind": "BATCH_ROOT", "digest": digest}},
                       {"subject": {"kind": "RECORD", "digest": "11" * 32}}, {"renewals": [{"token": item["token"]}] * 33}]:
            with self.assertRaises(ValueError):
                validate_index(json.dumps(dict(index, items=[dict(item, **change)])).encode())
        for items in [[item, item], [item] * 1025]:
            with self.assertRaises(ValueError):
                validate_index(json.dumps(dict(index, items=items)).encode())


class ApiTest(unittest.TestCase):
    @NEEDS_SPECIFICATION
    def test_suite_case_through_the_library(self):
        case = os.path.join(ROOT, "conformance", "conformity-1", "cases", "package-1.0-complete")
        with open(os.path.join(case, "artifact.json"), "rb") as artifact, open(os.path.join(case, "trust.json"), "rb") as trust:
            report = verify_record(artifact.read(), json.load(trust))
        self.assertEqual((report["status"], report["closure"]), ("VERIFIED_WITH_LIMITATIONS", "COMPLETE"))

    def test_untrusted_input_never_raises(self):
        for value in [b"", b"{", b"[]", b"not-a-jwt", b'{"schema":"https://humanjudgment.org/ns/conformity-package/1.0","files":[{}]}', b"a.b.c~"]:
            self.assertEqual(verify_record(value, {"issuers": {}})["status"], "INVALID")


if __name__ == "__main__":
    unittest.main()
