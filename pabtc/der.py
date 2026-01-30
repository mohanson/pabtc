import pabtc.secp256k1
import typing

# Der encoding. See: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding
# Brife format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
# In bitcoin transactions, the signature is der encoded plus 1 byte of sighash_type, but this is not part of the der
# standard; rather, it's a requirement of the bitcoin protocol. Standard der serialization only processes the signature
# itself; the sighash_type is appended at the bitcoin script level.


def encode(r: pabtc.secp256k1.Fr, s: pabtc.secp256k1.Fr) -> bytearray:
    body = bytearray()
    body.append(0x02)
    rbuf = bytearray(r.x.to_bytes(32)).lstrip(bytearray([0x00]))
    if rbuf[0] & 0x80:
        rbuf = bytearray([0x00]) + rbuf
    body.append(len(rbuf))
    body.extend(rbuf)
    body.append(0x02)
    sbuf = bytearray(s.x.to_bytes(32)).lstrip(bytearray([0x00]))
    if sbuf[0] & 0x80:
        sbuf = bytearray([0x00]) + sbuf
    body.append(len(sbuf))
    body.extend(sbuf)
    head = bytearray([0x30, len(body)])
    return head + body


def decode(sign: bytearray) -> typing.Tuple[pabtc.secp256k1.Fr, pabtc.secp256k1.Fr]:
    assert sign[0] == 0x30
    assert sign[1] == len(sign) - 2
    assert sign[2] == 0x02
    rlen = sign[3]
    r = pabtc.secp256k1.Fr(int.from_bytes(sign[4:4+rlen]))
    f = 4 + rlen
    assert sign[f] == 0x02
    slen = sign[f+1]
    f = f + 2
    s = pabtc.secp256k1.Fr(int.from_bytes(sign[f:f+slen]))
    return r, s
