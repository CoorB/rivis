"""qr — a small QR code encoder (byte mode, error correction level M, versions 1-6: up to 106 bytes). Stdlib only.

Used for the phone setup link (http://<this Mac>:<port>/), so a phone's camera opens the setup page without typing.
Follows ISO/IEC 18004: Reed-Solomon over GF(256) (0x11D), the eight masks scored by the four penalty rules.

  qr.matrix(text) -> list of rows of bools (True = dark), without the quiet zone
  qr.svg(text)    -> an <svg> with a 4-module quiet zone
"""

# level M, versions 1-6: (error correction codewords per block, number of blocks, data codewords per block)
_BLOCKS = {1: (10, 1, 16), 2: (16, 1, 28), 3: (26, 1, 44), 4: (18, 2, 32), 5: (24, 2, 43), 6: (16, 4, 27)}
_FORMAT_M = 0          # error correction level bits for M


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _codewords(data):
    """Byte-mode bit stream → interleaved data + error correction codewords, and the version used."""
    for version, (ec, nblocks, per) in sorted(_BLOCKS.items()):
        capacity = nblocks * per
        if 4 + 8 + 8 * len(data) <= capacity * 8:
            break
    else:
        raise ValueError("text too long for a QR code here (%d bytes; at most 106)" % len(data))
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(8))]
    for b in data:
        bits += [(b >> i) & 1 for i in reversed(range(8))]
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    divisor = _rs_divisor(ec)
    blocks = [words[i * per:(i + 1) * per] for i in range(nblocks)]
    eccs = [_rs_remainder(b, divisor) for b in blocks]
    out = [b[i] for i in range(per) for b in blocks] + [e[i] for i in range(ec) for e in eccs]
    return version, out


def _penalty(m):
    n = len(m)
    score = 0
    lines = m + [list(col) for col in zip(*m)]
    for line in lines:                                   # N1: runs of five or more of one colour
        run, prev = 0, None
        for v in line + [None]:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run, prev = 1, v
    for r in range(n - 1):                               # N2: 2x2 blocks of one colour
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    finder = [True, False, True, True, True, False, True]
    light = [False] * 4
    for line in lines:                                   # N3: finder-like 1:1:3:1:1 with four light modules beside it
        for i in range(n - 10):
            window = line[i:i + 11]
            if window == finder + light or window == light + finder:
                score += 40
    dark = sum(map(sum, m))                              # N4: balance of dark and light
    score += 10 * (abs(dark * 20 - n * n * 10) // (n * n))
    return score


def matrix(text):
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    version, words = _codewords(data)
    size = 17 + 4 * version
    mods = [[False] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        mods[y][x] = dark
        func[y][x] = True

    for i in range(size):                                # timing patterns
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):    # finder patterns with their separators
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    put(x, y, max(abs(dx), abs(dy)) not in (2, 4))
    if version >= 2:                                     # versions 2-6 have one alignment pattern
        p = size - 7
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                put(p + dx, p + dy, max(abs(dx), abs(dy)) != 1)

    def format_bits(mask):
        d = _FORMAT_M << 3 | mask
        rem = d
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (d << 10 | rem) ^ 0x5412
        b = lambda i: (bits >> i) & 1 != 0
        for i in range(6):
            put(8, i, b(i))
        put(8, 7, b(6))
        put(8, 8, b(7))
        put(7, 8, b(8))
        for i in range(9, 15):
            put(14 - i, 8, b(i))
        for i in range(8):
            put(size - 1 - i, 8, b(i))
        for i in range(8, 15):
            put(8, size - 15 + i, b(i))
        put(8, size - 8, True)                           # the dark module

    format_bits(0)                                       # reserve the format areas before placing data
    i, total = 0, len(words) * 8
    for right in range(size - 1, 0, -2):
        if right <= 6:
            right -= 1
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not func[y][x] and i < total:
                    mods[y][x] = (words[i >> 3] >> (7 - (i & 7))) & 1 != 0
                    i += 1
    masks = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
             lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
             lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
             lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]
    base = [row[:] for row in mods]
    best = None
    for k, f in enumerate(masks):
        for y in range(size):
            for x in range(size):
                mods[y][x] = base[y][x] ^ (not func[y][x] and f(x, y))
        format_bits(k)
        score = _penalty(mods)
        if best is None or score < best[0]:
            best = (score, [row[:] for row in mods])
    return best[1]


def svg(text, module=4, label=None):
    m = matrix(text)
    n = len(m) + 8
    path = "".join("M%d %dh1v1h-1z" % (x + 4, y + 4) for y, row in enumerate(m) for x, v in enumerate(row) if v)
    title = "<title>%s</title>" % (label or "").replace("&", "&amp;").replace("<", "&lt;") if label else ""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" '
            'role="img">%s<rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>'
            % (n, n, n * module, n * module, title, n, n, path))


def png(text, module=8):
    """A PNG of the code (used by the tests to have it read back by a real QR decoder)."""
    import struct
    import zlib
    m = matrix(text)
    n = (len(m) + 8) * module
    rows = []
    for y in range(n):
        my = y // module - 4
        row = bytearray([0])
        for x in range(n):
            mx = x // module - 4
            dark = 0 <= my < len(m) and 0 <= mx < len(m) and m[my][mx]
            row.append(0 if dark else 255)
        rows.append(bytes(row))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))
