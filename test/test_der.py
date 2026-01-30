import pabtc
import secrets


def test_der():
    for _ in range(256):
        r0 = pabtc.secp256k1.Fr(max(1, secrets.randbelow(pabtc.secp256k1.N)))
        s0 = pabtc.secp256k1.Fr(max(1, secrets.randbelow(pabtc.secp256k1.N)))
        r1, s1 = pabtc.der.decode(pabtc.der.encode(r0, s0))
        assert r0 == r1
        assert s0 == s1
