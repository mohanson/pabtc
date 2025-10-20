import itertools
import secrets
import typing
import pabtc.secp256k1



def sign(prikey: pabtc.secp256k1.Fr, m: pabtc.secp256k1.Fr) -> typing.Tuple[pabtc.secp256k1.Fr, pabtc.secp256k1.Fr, int]:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.3 Signing Operation
    for _ in itertools.repeat(0):
        k = pabtc.secp256k1.Fr(max(1, secrets.randbelow(pabtc.secp256k1.N)))
        R = pabtc.secp256k1.G * k
        r = pabtc.secp256k1.Fr(R.x.x)
        if r.x == 0:
            continue
        s = (m + prikey * r) / k
        if s.x == 0:
            continue
        v = 0
        if R.y.x & 1 == 1:
            v |= 1
        if R.x.x >= pabtc.secp256k1.N:
            v |= 2
        return r, s, v
    raise Exception('unreachable')


def verify(pubkey: pabtc.secp256k1.Pt, m: pabtc.secp256k1.Fr, r: pabtc.secp256k1.Fr, s: pabtc.secp256k1.Fr) -> bool:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.4 Verifying Operation
    a = m / s
    b = r / s
    R = pabtc.secp256k1.G * a + pubkey * b
    assert R != pabtc.secp256k1.I
    return r == pabtc.secp256k1.Fr(R.x.x)


def pubkey(m: pabtc.secp256k1.Fr, r: pabtc.secp256k1.Fr, s: pabtc.secp256k1.Fr, v: int) -> pabtc.secp256k1.Pt:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.6 Public Key Recovery Operation
    assert v in [0, 1, 2, 3]
    if v & 2 == 0:
        x = pabtc.secp256k1.Fq(r.x)
    else:
        x = pabtc.secp256k1.Fq(r.x + pabtc.secp256k1.N)
    z = x * x * x + pabtc.secp256k1.A * x + pabtc.secp256k1.B
    y = z ** ((pabtc.secp256k1.P + 1) // 4)
    if v & 1 != y.x & 1:
        y = -y
    R = pabtc.secp256k1.Pt(x, y)
    return (R * s - pabtc.secp256k1.G * m) / r
