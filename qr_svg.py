"""
Pure-Python ISO/IEC 18004 QR Code SVG Generator for TrustAudit MFA.

Generates crisp, offline, zero-external-API inline SVG QR codes for otpauth:// TOTP URIs
so authenticator secrets NEVER leave TrustAudit servers to third-party QR image services.
Supports UTF-8 Byte mode, Versions 1..10, Error Correction Level M, and automatic mask scoring.
"""

import html
from typing import Dict, List, Tuple

# GF(256) log / exp tables with primitive polynomial 0x11D (285)
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree: int) -> List[int]:
    poly = [1]
    for i in range(degree):
        root = _GF_EXP[i]
        nxt = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            nxt[j] ^= c
            nxt[j + 1] ^= _gf_mul(c, root)
        poly = nxt
    return poly


def _rs_remainder(data: List[int], ec_len: int) -> List[int]:
    gen = _rs_generator(ec_len)
    res = list(data) + [0] * ec_len
    for i in range(len(data)):
        coef = res[i]
        if coef != 0:
            for j in range(1, len(gen)):
                res[i + j] ^= _gf_mul(gen[j], coef)
    return res[len(data):]


# Error Correction Level M specification per version (1..10):
# (total_data_codewords, ec_per_block, [(count1, data1), (count2, data2)])
_VERSION_M_SPECS: Dict[int, Tuple[int, int, List[Tuple[int, int]]]] = {
    1: (16, 10, [(1, 16)]),
    2: (28, 16, [(1, 28)]),
    3: (44, 26, [(1, 44)]),
    4: (64, 18, [(2, 32)]),
    5: (86, 24, [(2, 43)]),
    6: (108, 16, [(4, 27)]),
    7: (124, 18, [(4, 31)]),
    8: (154, 22, [(2, 38), (2, 39)]),
    9: (182, 22, [(3, 36), (2, 37)]),
    10: (216, 26, [(4, 43), (1, 44)]),
}

_ALIGNMENT_CENTERS = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
}

# Precomputed 15-bit format info (BCH(15,5) + mask 0x5412) for ECC M (00) and masks 0..7
_FORMAT_INFO_M = [
    0x5412 ^ 0x5412,  # placeholder replaced programmatically below
]


def _compute_format_bits(ecc_bits: int, mask_id: int) -> int:
    data = (ecc_bits << 3) | mask_id
    rem = data << 10
    gen = 0b10100110111
    for bit in range(14, 9, -1):
        if rem & (1 << bit):
            rem ^= gen << (bit - 10)
    raw = ((data << 10) | rem) ^ 0b101010000010010
    return raw


def _compute_version_bits(ver: int) -> int:
    if ver < 7:
        return 0
    rem = ver << 12
    gen = 0b1111100100101
    for bit in range(17, 11, -1):
        if rem & (1 << bit):
            rem ^= gen << (bit - 12)
    return (ver << 12) | rem


def _choose_version(byte_len: int) -> int:
    for ver in range(1, 11):
        cap_cw = _VERSION_M_SPECS[ver][0]
        header_bits = 4 + (8 if ver <= 9 else 16)
        if header_bits + byte_len * 8 <= cap_cw * 8:
            return ver
    raise ValueError("URI exceeds supported QR Version 10 capacity.")


def _encode_bytes_m(raw: bytes) -> Tuple[int, List[int]]:
    ver = _choose_version(len(raw))
    total_data_cw, ec_len, blocks_spec = _VERSION_M_SPECS[ver]

    bits: List[int] = []

    def push(val: int, width: int) -> None:
        for b in range(width - 1, -1, -1):
            bits.append((val >> b) & 1)

    push(0b0100, 4)  # Byte mode indicator
    push(len(raw), 8 if ver <= 9 else 16)
    for byte in raw:
        push(byte, 8)

    max_bits = total_data_cw * 8
    term = min(4, max_bits - len(bits))
    push(0, term)
    while len(bits) % 8 != 0:
        bits.append(0)

    data_cw: List[int] = []
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        data_cw.append(v)

    pad_bytes = (0xEC, 0x11)
    p_idx = 0
    while len(data_cw) < total_data_cw:
        data_cw.append(pad_bytes[p_idx % 2])
        p_idx += 1

    # Split into blocks and compute RS ECC
    data_blocks: List[List[int]] = []
    ec_blocks: List[List[int]] = []
    pos = 0
    for count, size in blocks_spec:
        for _ in range(count):
            blk = data_cw[pos:pos + size]
            pos += size
            data_blocks.append(blk)
            ec_blocks.append(_rs_remainder(blk, ec_len))

    interleaved: List[int] = []
    max_d = max(len(b) for b in data_blocks)
    for i in range(max_d):
        for blk in data_blocks:
            if i < len(blk):
                interleaved.append(blk[i])
    for i in range(ec_len):
        for blk in ec_blocks:
            interleaved.append(blk[i])

    # Remainder bits (Versions 2-6 require 7 bits; 1 uses 0; 7-10 require 0)
    return ver, interleaved


def _build_base_matrix(ver: int) -> Tuple[List[List[int]], List[List[bool]]]:
    n = 17 + 4 * ver
    grid = [[0] * n for _ in range(n)]
    reserved = [[False] * n for _ in range(n)]

    def set_fn(r: int, c: int, val: int) -> None:
        if 0 <= r < n and 0 <= c < n:
            grid[r][c] = val
            reserved[r][c] = True

    def place_finder(r0: int, c0: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if not (0 <= r < n and 0 <= c < n):
                    continue
                if dr in (-1, 7) or dc in (-1, 7):
                    set_fn(r, c, 0)
                elif dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4):
                    set_fn(r, c, 1)
                else:
                    set_fn(r, c, 0)

    place_finder(0, 0)
    place_finder(0, n - 7)
    place_finder(n - 7, 0)

    centers = _ALIGNMENT_CENTERS[ver]
    for cr in centers:
        for cc in centers:
            if (cr <= 8 and cc <= 8) or (cr <= 8 and cc >= n - 9) or (cr >= n - 9 and cc <= 8):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    val = 1 if (abs(dr) == 2 or abs(dc) == 2 or (dr == 0 and dc == 0)) else 0
                    set_fn(cr + dr, cc + dc, val)

    for i in range(8, n - 8):
        val = 1 if i % 2 == 0 else 0
        if not reserved[6][i]:
            set_fn(6, i, val)
        if not reserved[i][6]:
            set_fn(i, 6, val)

    # Dark module
    set_fn(4 * ver + 9, 8, 1)

    # Reserve format info areas
    for i in range(9):
        if not reserved[8][i]:
            reserved[8][i] = True
        if not reserved[i][8]:
            reserved[i][8] = True
    for i in range(n - 8, n):
        reserved[8][i] = True
    for i in range(n - 7, n):
        reserved[i][8] = True

    # Version info for >= 7
    if ver >= 7:
        vbits = _compute_version_bits(ver)
        for i in range(18):
            bit = (vbits >> i) & 1
            r = i // 3
            c = n - 11 + (i % 3)
            set_fn(r, c, bit)
            set_fn(c, r, bit)

    return grid, reserved


def _apply_format_info(grid: List[List[int]], mask_id: int) -> None:
    n = len(grid)
    fmt = _compute_format_bits(0b00, mask_id)  # ECC Level M = 00
    coords1 = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
               (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    coords2 = [(n - 1, 8), (n - 2, 8), (n - 3, 8), (n - 4, 8), (n - 5, 8), (n - 6, 8), (n - 7, 8),
               (8, n - 8), (8, n - 7), (8, n - 6), (8, n - 5), (8, n - 4), (8, n - 3), (8, n - 2), (8, n - 1)]
    for idx in range(15):
        bit = (fmt >> (14 - idx)) & 1
        r1, c1 = coords1[idx]
        r2, c2 = coords2[idx]
        grid[r1][c1] = bit
        grid[r2][c2] = bit


def _mask_condition(mask_id: int, r: int, c: int) -> bool:
    if mask_id == 0:
        return (r + c) % 2 == 0
    if mask_id == 1:
        return r % 2 == 0
    if mask_id == 2:
        return c % 3 == 0
    if mask_id == 3:
        return (r + c) % 3 == 0
    if mask_id == 4:
        return ((r // 2) + (c // 3)) % 2 == 0
    if mask_id == 5:
        return ((r * c) % 2 + (r * c) % 3) == 0
    if mask_id == 6:
        return (((r * c) % 2 + (r * c) % 3) % 2) == 0
    return (((r + c) % 2 + (r * c) % 3) % 2) == 0


def _penalty_score(grid: List[List[int]]) -> int:
    n = len(grid)
    score = 0
    # Rule 1: adjacent modules
    for r in range(n):
        run = 1
        for c in range(1, n):
            if grid[r][c] == grid[r][c - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)
    for c in range(n):
        run = 1
        for r in range(1, n):
            if grid[r][c] == grid[r - 1][c]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)
    # Rule 2: 2x2 blocks
    for r in range(n - 1):
        for c in range(n - 1):
            v = grid[r][c]
            if v == grid[r][c + 1] == grid[r + 1][c] == grid[r + 1][c + 1]:
                score += 3
    return score


def generate_qr_matrix(text: str) -> List[List[int]]:
    """Generates a standard QR code module matrix (1 = dark, 0 = light)."""
    raw = text.encode("utf-8")
    ver, codewords = _encode_bytes_m(raw)
    bitstream: List[int] = []
    for cw in codewords:
        for b in range(7, -1, -1):
            bitstream.append((cw >> b) & 1)

    base_grid, reserved = _build_base_matrix(ver)
    n = len(base_grid)

    # Zigzag placement
    data_coords: List[Tuple[int, int]] = []
    up = True
    c = n - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(n - 1, -1, -1) if up else range(n)
        for r in rows:
            for dc in (0, -1):
                col = c + dc
                if not reserved[r][col]:
                    data_coords.append((r, col))
        c -= 2
        up = not up

    best_grid = None
    best_score = 10**9
    for mask_id in range(8):
        g = [row[:] for row in base_grid]
        for idx, (r, col) in enumerate(data_coords):
            bit = bitstream[idx] if idx < len(bitstream) else 0
            if _mask_condition(mask_id, r, col):
                bit ^= 1
            g[r][col] = bit
        _apply_format_info(g, mask_id)
        sc = _penalty_score(g)
        if sc < best_score:
            best_score = sc
            best_grid = g

    return best_grid or base_grid


def generate_qr_svg(text: str, module_size: int = 4, border: int = 4, dark: str = "#0B1F1A", light: str = "#FFFFFF") -> str:
    """Renders an inline SVG QR code with compact single-<path> geometry."""
    matrix = generate_qr_matrix(text)
    n = len(matrix)
    dim = (n + border * 2) * module_size
    parts: List[str] = []
    for r in range(n):
        for c in range(n):
            if matrix[r][c]:
                x = (c + border) * module_size
                y = (r + border) * module_size
                parts.append(f"M{x} {y}h{module_size}v{module_size}h-{module_size}z")
    path_d = "".join(parts)
    safe_title = html.escape("Scan QR Code in Authenticator App")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" '
        f'width="{dim}" height="{dim}" role="img" aria-label="{safe_title}" '
        f'style="background:{light};border-radius:10px;border:1px solid #d1e3dd;">'
        f'<rect width="{dim}" height="{dim}" fill="{light}"/>'
        f'<path d="{path_d}" fill="{dark}"/></svg>'
    )
