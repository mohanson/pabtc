# Copyright (c) 2017, 2020 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# BIP-0173 https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
# BIP-0350 https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
# Derived from https://raw.githubusercontent.com/sipa/bech32/master/ref/python/segwit_addr.py
#
# Reference implementation for Bech32/bech32 and segwit addresses.

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
CONST_0 = 1
CONST_M = 0x2bc830a3


def polymod(buf: bytearray) -> int:
    # Internal function that computes the bech32 checksum.
    assert isinstance(buf, bytearray)
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for val in buf:
        top = chk >> 25
        chk = chk & 0x1ffffff
        chk = chk << 5 ^ val
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def hrpconv(hrp: str) -> bytearray:
    # Expand the human readable part into values for checksum computation.
    r = bytearray()
    r.extend([ord(x) >> 5 for x in hrp])
    r.append(0)
    r.extend([ord(x) & 31 for x in hrp])
    return r


def re_arrange_5(buf: bytearray) -> bytearray:
    # Re-arrange those bits into groups of 5, and pad with zeroes at the end if needed.
    assert isinstance(buf, bytearray)
    acc = 0
    bit = 0
    ret = bytearray()
    max_val = 0x1f
    max_acc = 0xfff
    for b in buf:
        acc = ((acc << 8) | b) & max_acc
        bit += 8
        for _ in range(bit // 5):
            bit -= 5
            ret.append((acc >> bit) & max_val)
    if bit:
        pad_bit = 5 - bit
        ret.append((acc << pad_bit) & max_val)
    return ret


def re_arrange_8(buf: bytearray) -> bytearray:
    # Re-arrange those bits into groups of 8 bits. Any incomplete group at the end MUST be 4 bits or less, MUST be all
    # zeroes, and is discarded.
    assert isinstance(buf, bytearray)
    acc = 0
    bit = 0
    ret = bytearray()
    max_val = 0xff
    max_acc = 0xfff
    for b in buf:
        assert b <= 0x1f
        acc = ((acc << 5) | b) & max_acc
        bit += 5
        for _ in range(bit // 8):
            bit -= 8
            ret.append((acc >> bit) & max_val)
    assert bit < 5
    return ret


def create_checksum(hrp: str, ver: int, buf: bytearray) -> bytearray:
    bin = hrpconv(hrp) + buf
    chk = polymod(bin + bytearray(6))
    if ver == 0:
        chk = chk ^ CONST_0
    if ver >= 1:
        chk = chk ^ CONST_M
    return bytearray([(chk >> 5 * (5 - i)) & 31 for i in range(6)])


def verify_checksum(hrp: str, ver: int, buf: bytearray) -> bool:
    if ver == 0:
        return polymod(hrpconv(hrp) + bytearray(buf)) == CONST_0
    if ver >= 1:
        return polymod(hrpconv(hrp) + bytearray(buf)) == CONST_M
    return False


def encode(hrp: str, ver: int, buf: bytearray) -> str:
    # Create a bech32 string given hrp and data values. Parameter ver is used to compute the checksum, but is not
    # appended to the data. When ver >= 1, the checksum will be computed according to bip-350, aka bech32m.
    # See: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki.
    chk = buf + create_checksum(hrp, ver, buf)
    return hrp + '1' + ''.join([CHARSET[d] for d in chk])


def decode(hrp: str, ver: int, val: str) -> bytearray:
    # Validate a string, and determine human readable part and data.
    for c in val:
        assert ord(c) >= ord('!')
        assert ord(c) <= ord('~')
    val = val.lower()
    pos = val.rfind('1')
    assert pos > 0
    assert pos + 6 < len(val)
    for c in val[pos+1:]:
        assert c in CHARSET
    assert hrp == val[:pos]
    buf = bytearray([CHARSET.find(x) for x in val[pos+1:]])
    assert verify_checksum(hrp, ver, buf)
    return buf[:-6]


def encode_segwit_addr(hrp: str, ver: int, buf: bytearray) -> str:
    # Encode a segwit address.
    assert isinstance(buf, bytearray)
    r = encode(hrp, ver, bytearray([ver]) + re_arrange_5(buf))
    assert buf == decode_segwit_addr(hrp, ver, r)
    return r


def decode_segwit_addr(hrp: str, ver: int, val: str) -> bytearray:
    # Decode a segwit address.
    data = decode(hrp, ver, val)
    assert ver == data[0]
    return re_arrange_8(data[1:])
