"""OpenTimestamps v1 detached proofs with offline, receiver-checkpointed Bitcoin header linkage."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ._json import is_integer
from ._timestamp import iso

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108")


def require(value):
    if not value:
        raise ValueError("invalid Bitcoin evidence")


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, count):
        end = self.pos + count
        require(end <= len(self.data))
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def byte(self):
        return self.read(1)[0]

    def integer(self):
        value = 0
        for shift in (0, 7, 14, 21, 28):
            b = self.byte()
            require(shift < 28 or b <= 15)
            value |= (b & 127) << shift
            if b < 128:
                require(shift == 0 or b > 0)
                return value
        raise ValueError("oversize OpenTimestamps integer")

    def field(self, limit):
        size = self.integer()
        require(size <= limit)
        return self.read(size)

    def end(self):
        require(self.pos == len(self.data))


def attestations(proof, imprint):
    require(len(proof) <= 1024 * 1024)
    reader = Reader(proof)
    require(reader.read(len(MAGIC)) == MAGIC and reader.read(32).hex() == imprint)
    bitcoin = []
    pending = False
    nodes = 0

    def walk(message, depth):
        nonlocal nodes, pending
        nodes += 1
        require(nodes <= 4096 and depth <= 128 and len(message) <= 4096)
        seen = set()
        while True:
            tag = reader.byte()
            more = tag == 255
            if more:
                tag = reader.byte()
            if tag == 0:
                kind = reader.read(8).hex()
                payload = Reader(reader.field(8192))
                if kind == "0588960d73d71901":
                    height = payload.integer()
                    payload.end()
                    require(len(message) == 32)
                    bitcoin.append((height, message))
                elif kind == "83dfe30d2ef90c8e":
                    require(payload.field(1000))
                    payload.end()
                    pending = True
            else:
                arg = reader.field(4096) if tag in (240, 241) else b""
                require((tag, arg) not in seen)
                seen.add((tag, arg))
                if tag == 8:
                    out = sha256(message).digest()
                elif tag in (240, 241) and arg:
                    out = message + arg if tag == 240 else arg + message
                elif tag == 242:
                    out = message[::-1]
                elif tag == 243:
                    out = message.hex().encode("ascii")
                else:
                    raise ValueError("unknown OpenTimestamps operation")
                walk(out, depth + 1)
            if not more:
                break
    walk(bytes.fromhex(imprint), 0)
    reader.end()
    require(bitcoin or pending)
    return bitcoin


def hash256(header):
    return sha256(sha256(header).digest()).digest()


def number(header, offset):
    return int.from_bytes(header[offset:offset + 4], "little")


def target(bits):
    exponent, mantissa = bits >> 24, bits & 0x7fffff
    require(mantissa and not bits & 0x800000 and exponent <= 34)
    shift = 8 * (exponent - 3)
    return mantissa << shift if shift >= 0 else mantissa >> -shift


def verify_bitcoin(proof, imprint, params, headers=None, first=0):
    require(is_integer(first, 0) and is_integer(params["minConfirmations"], 1) and is_integer(params["powLimitBits"], 1, 0xffffffff))
    found = attestations(proof, imprint)
    reason = "BITCOIN_ANCHOR_PENDING"
    if headers is not None:
        require(0 < len(headers) <= 60000 * 80 and len(headers) % 80 == 0)
        count = len(headers) // 80
        def at(height):
            pos = int(height - first) * 80
            return headers[pos:pos + 80]
        cp = next((c for c in params["checkpoints"] if is_integer(c["height"], first, first + count - 1)
                   and at(c["height"]).hex() == c["headerHex"] and hash256(at(c["height"]))[::-1].hex() == c["hash"]), None)
        if cp is None:
            reason = "BITCOIN_CHECKPOINT_NOT_HELD"
        else:
            checkpoint = int(cp["height"])
            limit = target(int(params["powLimitBits"]))
            previous = at(first)
            for height in range(first + 1, first + count):
                header = at(height)
                require(header[4:36] == hash256(previous))
                if height > checkpoint:
                    t = target(number(header, 72))
                    old = target(number(previous, 72))
                    require(0 < t <= limit and int.from_bytes(hash256(header), "little") <= t)
                    require(t == old if height % 2016 else old // 4 <= t <= old * 4)
                    if height - first >= 11:
                        require(number(header, 68) > sorted(number(at(h), 68) for h in range(height - 11, height))[5])
                previous = header
            best, mismatch, missing = None, False, False
            for height, message in found:
                if not first <= height < first + count:
                    missing = True
                    continue
                header = at(height)
                seconds = number(header, 68)
                if header[36:68] != message or (height > checkpoint and seconds < number(at(checkpoint), 68)):
                    mismatch = True
                    continue
                confirmations = first + count - height
                time = datetime.fromtimestamp(seconds, timezone.utc)
                if confirmations >= params["minConfirmations"]:
                    report = {"status": "VERIFIED", "height": height, "blockTime": iso(time),
                              "blockHash": hash256(header)[::-1].hex(), "confirmations": confirmations}
                    if not best or best[0]["status"] != "VERIFIED" or height < best[0]["height"]:
                        best = report, "BITCOIN_POW_LINKED_NOT_FULL_NODE", iso(time + timedelta(hours=2))
                elif not best:
                    best = {"status": "PENDING", "height": height, "confirmations": confirmations}, reason, None
            if best:
                return best
            require(not mismatch or missing)
    report = {"status": "PENDING"}
    if found:
        report["height"] = min(h for h, _ in found)
    return report, reason, None
