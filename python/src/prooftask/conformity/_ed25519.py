"""Ed25519 signature verification (RFC 8032 section 5.1.7), pure Python, verification only.

Verification handles only public data, so constant-time arithmetic is not required. The check is the
cofactorless equation encode([S]B - [k]A) == R, with S < L and canonical point encodings, which is what
OpenSSL (and therefore the Node.js reference verifier) accepts. Tested against the RFC 8032 section 7.1 vectors.
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point):
    zinv = _inv(point[2])
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data):
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def verify(public_key, message, signature):
    """True when `signature` is a valid Ed25519 signature of `message` under the 32-byte `public_key`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decode(public_key)
    if a is None or _decode(signature[:32]) is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    neg_a = (P - a[0], a[1], a[2], P - a[3])
    return _encode(_add(_mul(s, BASE), _mul(k, neg_a))) == signature[:32]


_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def public_key_from_pem(pem):
    """The raw 32-byte key of an Ed25519 SubjectPublicKeyInfo PEM; None for any other key type."""
    import base64
    lines = [line.strip() for line in pem.strip().splitlines()]
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        return None
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        return None
    if len(der) != 44 or not der.startswith(_SPKI_PREFIX):
        return None
    return der[12:]
