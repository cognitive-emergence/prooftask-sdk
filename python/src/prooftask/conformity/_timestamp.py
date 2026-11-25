"""Offline RFC 3161 / CMS validation. Package certificates are path candidates, never roots."""
import base64
import hashlib
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from typing import NamedTuple


def require(value):
    if not value:
        raise ValueError("invalid timestamp evidence")


class Node(NamedTuple):
    tag: int
    raw: bytes
    content: bytes

    def as_tag(self, tag):
        require(self.tag == tag)
        return self

    def fields(self):
        return nodes(self.content)

    def number(self):
        data = self.content
        require(0 < len(data) <= 32 and data[0] < 128 and (len(data) == 1 or data[0] or data[1] >= 128))
        return int.from_bytes(data, "big")

    def oid(self):
        self.as_tag(6)
        arcs = []
        n = 0
        for b in self.content:
            require(n < (1 << 56) and (n or b != 128))
            n = n * 128 + (b & 127)
            if b < 128:
                arcs.append(n)
                n = 0
        require(arcs and self.content[-1] < 128)
        first = min(arcs[0] // 40, 2)
        return ".".join(map(str, [first, arcs[0] - 40 * first] + arcs[1:]))


def nodes(data):
    result = []
    pos = 0
    while pos < len(data):
        require(len(result) < 20000 and pos + 2 <= len(data))
        tag, size = data[pos:pos + 2]
        start = pos + 2
        require(tag & 31 != 31)
        if size & 128:
            count = size & 127
            require(0 < count <= 4 and start + count <= len(data) and data[start] != 0)
            size = int.from_bytes(data[start:start + count], "big")
            require(size >= 128)
            start += count
        end = start + size
        require(end <= len(data))
        result.append(Node(tag, data[pos:end], data[start:end]))
        pos = end
    return result


def single(data, tag=48):
    fields = nodes(data)
    require(len(fields) == 1)
    return fields[0].as_tag(tag)


def time_value(node):
    value = node.content.decode("ascii")
    if node.tag == 23:
        require(re.fullmatch(r"[0-9]{12}Z", value))
        value = ("19" if int(value[:2]) >= 50 else "20") + value
    else:
        node.as_tag(24)
    require(re.fullmatch(r"[0-9]{14}(?:\.[0-9]{1,6})?Z", value))
    fmt = "%Y%m%d%H%M%S.%fZ" if "." in value else "%Y%m%d%H%M%SZ"
    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)


def iso(at, upper=False):
    if upper and at.microsecond % 1000:
        at += timedelta(microseconds=1000 - at.microsecond % 1000)
    return at.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pem_blocks(pem, label):
    pattern = rb"-----BEGIN " + label + rb"-----([a-zA-Z0-9+/=\s]+?)-----END " + label + rb"-----"
    for match in re.finditer(pattern, pem):
        yield base64.b64decode(b"".join(match.group(1).split()), validate=True)


SHA256 = "2.16.840.1.101.3.4.2.1"
HASH = {"1.3.14.3.2.26": "sha1", SHA256: "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
RSA = "1.2.840.113549.1.1."
RSA_HASH = {RSA + str(i): h for i, h in [(11, "sha256"), (12, "sha384"), (13, "sha512")]}
EC_HASH = {"1.2.840.10045.4.3." + str(i): h for i, h in [(2, "sha256"), (3, "sha384"), (4, "sha512")]}
DIGEST_INFO = {h: bytes.fromhex("30" + s + "300d060960864801650304020" + oid + "050004" + n)
               for h, s, oid, n in [("sha256", "31", "1", "20"), ("sha384", "41", "2", "30"), ("sha512", "51", "3", "40")]}
TST_INFO = "1.2.840.113549.1.9.16.1.4"


def algorithm(node):
    return node.as_tag(48).fields()[0].oid()


def check_signature(spki, alg, signature, data, cms_hash=None):
    """RSASSA-PKCS1-v1_5 (RFC 8017, §8.2). ECDSA uses the system openssl dgst primitive."""
    key_alg, bits = spki.fields()
    if alg == RSA + "1" or alg in RSA_HASH:
        h = cms_hash if alg == RSA + "1" else RSA_HASH[alg]
        require(h in DIGEST_INFO and (not cms_hash or h == cms_hash) and algorithm(key_alg) == RSA + "1")
        require(bits.as_tag(3).content[0] == 0)
        n, e = [v.as_tag(2).content for v in single(bits.content[1:]).fields()]
        n, e = int.from_bytes(n, "big"), int.from_bytes(e, "big")
        width = (n.bit_length() + 7) // 8
        require(128 <= width <= 1024 and 3 <= e <= 2**32 and e % 2 == 1 and len(signature) == width)
        sig = int.from_bytes(signature, "big")
        require(sig < n)
        actual = pow(sig, e, n).to_bytes(width, "big")
        suffix = DIGEST_INFO[h] + hashlib.new(h, data).digest()
        require(width >= len(suffix) + 11 and actual == b"\x00\x01" + b"\xff" * (width - len(suffix) - 3) + b"\x00" + suffix)
    else:
        require(alg in EC_HASH and (not cms_hash or cms_hash == EC_HASH[alg]) and algorithm(key_alg) == "1.2.840.10045.2.1")
        with tempfile.TemporaryDirectory() as directory:
            key_file, sig_file = [os.path.join(directory, n) for n in ("public.pem", "signature.der")]
            with open(key_file, "wb") as f:
                f.write(b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki.raw) + b"-----END PUBLIC KEY-----\n")
            with open(sig_file, "wb") as f:
                f.write(signature)
            result = subprocess.run(["openssl", "dgst", "-" + EC_HASH[alg], "-verify", key_file, "-signature", sig_file],
                                    input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            require(result.returncode == 0)


def extensions(node):
    result = {}
    for field in node.as_tag(48).fields():
        parts = field.as_tag(48).fields()
        require(len(parts) in (2, 3))
        oid = parts[0].oid()
        require(oid not in result)
        critical = len(parts) == 3
        if critical:
            require(parts[1].as_tag(1).content == b"\xff")
        result[oid] = (critical, parts[-1].as_tag(4).content)
    return result


class Signed:
    def __init__(self, data):
        self.raw = data
        self.tbs, alg, bits = single(data).fields()
        self.alg = algorithm(alg)
        self.tbs.as_tag(48)
        require(bits.as_tag(3).content[:1] == b"\0")
        self.signature = bits.content[1:]

    def signed_by(self, cert):
        if self.issuer != cert.subject:
            return False
        try:
            check_signature(cert.spki, self.alg, self.signature, self.tbs.raw)
            return True
        except (ValueError, KeyError, IndexError, OSError, subprocess.SubprocessError):
            return False


class Certificate(Signed):
    def __init__(self, data):
        super().__init__(data)
        fields = self.tbs.fields()
        if fields[0].tag == 160:
            fields = fields[1:]
        serial, alg, issuer, times, subject, self.spki = fields[:6]
        require(algorithm(alg) == self.alg)
        self.serial = serial.as_tag(2).number()
        self.issuer, self.subject = issuer.as_tag(48).raw, subject.as_tag(48).raw
        self.start, self.end = [time_value(x) for x in times.as_tag(48).fields()]
        self.ext = {}
        for field in fields[6:]:
            if field.tag == 163:
                self.ext = extensions(single(field.content))

    def usage(self, flag):
        ext = self.ext.get("2.5.29.15")
        return bool(ext and single(ext[1], 3).content[1] & flag)

    def ca_at_depth(self, subordinate):
        ext = self.ext.get("2.5.29.19")
        if not ext or not self.usage(4):
            return False
        fields = single(ext[1]).fields()
        return fields and fields[0].as_tag(1).content == b"\xff" and (len(fields) == 1 or fields[1].as_tag(2).number() >= subordinate)


class Crl(Signed):
    def __init__(self, data):
        super().__init__(data)
        fields = self.tbs.fields()
        if fields[0].tag == 2:
            fields = fields[1:]
        alg, issuer, update = fields[:3]
        require(algorithm(alg) == self.alg)
        self.issuer, self.update = issuer.as_tag(48).raw, time_value(update)
        tail = fields[3:]
        if tail and tail[0].tag in (23, 24):
            time_value(tail[0])
            tail = tail[1:]
        self.revoked, self.complete = set(), True
        if tail and tail[0].tag == 48:
            for entry in tail[0].fields():
                parts = entry.as_tag(48).fields()
                self.revoked.add(parts[0].as_tag(2).number())
                if len(parts) > 2 and any(critical for critical, _ in extensions(parts[2]).values()):
                    self.complete = False
            tail = tail[1:]
        if tail:
            exts = extensions(single(tail[0].as_tag(160).content))
            if {"2.5.29.27", "2.5.29.28"} & exts.keys() or any(critical and k not in ("2.5.29.20", "2.5.29.35")
                                                                   for k, (critical, _) in exts.items()):
                self.complete = False


def common_name(subject):
    for rdn in single(subject).fields():
        for attr in rdn.as_tag(49).fields():
            oid, value = attr.as_tag(48).fields()
            if oid.oid() == "2.5.4.3":
                return value.content.decode("utf-8", "replace")[:200]
    return ""


def check_attributes(attrs, signer, content, digest):
    found = {}
    for attr in attrs.as_tag(160).fields():
        name, values = attr.as_tag(48).fields()
        oid = name.oid()
        require(oid not in found)
        found[oid] = values.as_tag(49).fields()
    def one(oid):
        require(len(found[oid]) == 1)
        return found[oid][0]
    require(one("1.2.840.113549.1.9.3").oid() == TST_INFO)
    require(one("1.2.840.113549.1.9.4").as_tag(4).content == hashlib.new(digest, content).digest())
    refs = {"1.2.840.113549.1.9.16.2.12": "sha1", "1.2.840.113549.1.9.16.2.47": "sha256"}
    require(refs.keys() & found.keys())
    for oid, default in refs.items():
        if oid not in found:
            continue
        first = one(oid).as_tag(48).fields()[0].as_tag(48).fields()[0].as_tag(48).fields()
        h = default
        if default == "sha256" and first[0].tag == 48:
            h = HASH[algorithm(first[0])]
            require(h != "sha1")
            first = first[1:]
        require(first[0].as_tag(4).content == hashlib.new(h, signer.raw).digest())
        require(len(first) in (1, 2))
        if len(first) == 2:
            names, serial = first[1].as_tag(48).fields()
            require(serial.as_tag(2).number() == signer.serial and any(n.tag == 164 and n.content == signer.issuer for n in names.as_tag(48).fields()))


def prepare_validation(roots, validation):
    require(len(validation) <= 1024 * 1024)
    validation.decode("utf-8")
    pool = []
    trusted = [Certificate(der) for root in roots for der in pem_blocks(root["pem"].encode("ascii"), b"CERTIFICATE")]
    require(trusted and len(trusted) <= 128)
    for der in pem_blocks(validation, b"CERTIFICATE"):
        try:
            pool.append(Certificate(der))
        except (ValueError, IndexError):
            pass
    require(len(pool) <= 128)
    crls = []
    for der in pem_blocks(validation, b"X509 CRL"):
        require(len(crls) < 128)
        try:
            crls.append(Crl(der))
        except (ValueError, IndexError):
            pass
    return trusted, pool, crls


def timestamp(token, imprint, roots, validation=b"", policies=None, material=None):
    require(0 < len(token) <= 65536 and len(validation) <= 1024 * 1024)
    kind, explicit = single(token).fields()
    require(kind.oid() == "1.2.840.113549.1.7.2")
    signed = single(explicit.as_tag(160).content).fields()
    kind, encap = signed[2].as_tag(48).fields()
    require(kind.oid() == TST_INFO)
    content = single(encap.as_tag(160).content, 4).content
    info = single(content).fields()
    require(info[0].as_tag(2).number() == 1)
    policy = info[1].oid()
    if policies and policy not in policies:
        raise ValueError("TRUST_TIME_POLICY_MISMATCH")
    alg, message = info[2].as_tag(48).fields()
    require(algorithm(alg) == SHA256 and message.as_tag(4).content == bytes.fromhex(imprint))
    require(len(alg.fields()) == 1 or (len(alg.fields()) == 2 and alg.fields()[1].raw == b"\x05\0"))
    info[3].as_tag(2).number()
    gen = time_value(info[4].as_tag(24))
    accuracy = timedelta(0)
    if len(info) > 5 and info[5].tag == 48:
        last = -1
        for part in info[5].fields():
            i = (2, 128, 129).index(part.tag)
            n = part.number()
            require(i > last and (i == 0 or 1 <= n <= 999))
            last = i
            accuracy += timedelta(microseconds=n * (1000000, 1000, 1)[i])
    pool = []
    for field in signed[3:-1]:
        if field.tag == 160:
            pool.extend(Certificate(c.raw) for c in field.fields() if c.tag == 48)
    if material is None:
        material = prepare_validation(roots, validation)
    trusted, extra, crls = material
    pool.extend(extra)
    require(len(pool) <= 128)
    si = single(signed[-1].as_tag(49).content).fields()
    sid = si[1]
    if sid.tag == 48:
        issuer, serial = sid.fields()
        signer = next((c for c in pool if c.issuer == issuer.raw and c.serial == serial.as_tag(2).number()), None)
    else:
        ski = sid.as_tag(128).content
        signer = next((c for c in pool if "2.5.29.14" in c.ext and single(c.ext["2.5.29.14"][1], 4).content == ski), None)
    require(signer is not None)
    digest = HASH[algorithm(si[2])]
    require(digest != "sha1" and algorithm(si[2]) in [algorithm(a) for a in signed[1].as_tag(49).fields()])
    check_attributes(si[3], signer, content, digest)
    check_signature(signer.spki, algorithm(si[4]), si[5].as_tag(4).content, b"\x31" + si[3].raw[1:], digest)
    critical, eku = signer.ext["2.5.29.37"]
    require(critical and [v.oid() for v in single(eku).fields()] == ["1.3.6.1.5.5.7.3.8"])
    chain = [signer]
    while len(chain) <= 6:
        current = chain[-1]
        root = next((r for r in trusted if current.signed_by(r)), None)
        if root is not None:
            break
        parent = next((c for c in pool if c not in chain and c.subject == current.issuer
                       and c.ca_at_depth(len(chain) - 1) and current.signed_by(c)), None)
        require(parent is not None)
        chain.append(parent)
    else:
        raise ValueError("certificate chain too deep")
    require(all(c.start <= gen <= c.end for c in chain + [root]))
    # A critical usage or policy constraint we cannot interpret must never widen a certificate's authority.
    for c in chain:
        require(all(not critical or oid in ("2.5.29.15", "2.5.29.19", "2.5.29.37") for oid, (critical, _) in c.ext.items()))
        if "2.5.29.37" in c.ext:
            uses = [v.oid() for v in single(c.ext["2.5.29.37"][1]).fields()]
            require("1.3.6.1.5.5.7.3.8" in uses or "2.5.29.37.0" in uses)
    if "2.5.29.15" in signer.ext:
        require(signer.usage(128) or signer.usage(64))
    covered = True
    for child, parent in zip(chain, chain[1:] + [root]):
        authentic = [c for c in crls if c.signed_by(parent)] if parent.usage(2) else []
        require(not any(child.serial in c.revoked for c in authentic))
        if not any(c.complete and gen + timedelta(days=1) <= c.update < child.end for c in authentic):
            covered = False
    return {"status": "VERIFIED", "genTime": iso(gen), "latestTime": iso(gen + accuracy, upper=True), "policy": policy,
            "tsa": common_name(signer.subject), "revocation": "CHECKED" if covered else "NOT_CHECKED"}
