import pabtc.schnorr
import pabtc.secp256k1


def prikey_tweak(prikey: pabtc.secp256k1.Fr, merkle: bytearray) -> pabtc.secp256k1.Fr:
    # Compute the secret key for a tweaked public key.
    origin_prikey = pabtc.schnorr.prikey_implicit(prikey)
    origin_pubkey = pabtc.secp256k1.G * prikey
    adjust_prikey_byte = pabtc.schnorr.hash('TapTweak', bytearray(origin_pubkey.x.n.to_bytes(32)) + merkle)
    adjust_prikey = pabtc.secp256k1.Fr(int.from_bytes(adjust_prikey_byte))
    output_prikey = origin_prikey + adjust_prikey
    return output_prikey


def pubkey_tweak(pubkey: pabtc.secp256k1.Pt, merkle: bytearray) -> pabtc.secp256k1.Pt:
    # Taproot. See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    # Taproot requires that the y coordinate of the public key is even.
    origin_pubkey = pabtc.schnorr.pubkey_implicit(pubkey)
    # There is no script path if root is empty.
    assert len(merkle) in [0x00, 0x20]
    adjust_prikey_byte = pabtc.schnorr.hash('TapTweak', bytearray(origin_pubkey.x.n.to_bytes(32)) + merkle)
    adjust_prikey = pabtc.secp256k1.Fr(int.from_bytes(adjust_prikey_byte))
    adjust_pubkey = pabtc.secp256k1.G * adjust_prikey
    output_pubkey = origin_pubkey + adjust_pubkey
    return output_pubkey
