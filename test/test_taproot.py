import pabtc
import random


def test_prikey_tweak():
    for _ in range(4):
        prikey = pabtc.core.PriKey.random()
        prikey = pabtc.secp256k1.Fr(prikey.n)
        pubkey = pabtc.secp256k1.G * prikey
        merkle = bytearray(random.randbytes(32))
        pubkey_tweak = pabtc.taproot.pubkey_tweak(pubkey, merkle)
        prikey_tweak = pabtc.taproot.prikey_tweak(prikey, merkle)
        assert pubkey_tweak == pabtc.secp256k1.G * prikey_tweak
