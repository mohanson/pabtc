import pabtc

# This example shows how to create a P2MR script with two unlock conditions: p2pk and p2ms.


# Here created two scripts, one of which is a p2pk script, which requires that it can only be unlocked by private key 2,
# and the other is an 2-of-2 multisig script.
mast = pabtc.core.TapBranch(
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2pk(pabtc.core.PriKey(2).pubkey())),
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2ms(2, [pabtc.core.PriKey(3).pubkey(), pabtc.core.PriKey(4).pubkey()])),
)
root = mast.hash


class Signerp2mrp2pk(pabtc.wallet.Signer):
    def __init__(self) -> None:
        self.script = pabtc.core.ScriptPubKey.p2mr(root)
        # In p2tr, the least significant bit is the parity bit of the output public key's y-coordinate, which can be
        # either 0 or 1. In p2mr, which has no internal key/key path cost, this bit is always 1.
        self.prefix = 0xc0 + 1
        self.addr = pabtc.core.Address.p2mr(root)

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.l, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.l.script)
            e.witness = [
                pabtc.core.PriKey(2).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                mast.l.script,
                bytearray([self.prefix]) + mast.r.hash,
            ]


class Signerp2mrp2ms(pabtc.wallet.Signer):
    def __init__(self) -> None:
        self.script = pabtc.core.ScriptPubKey.p2mr(root)
        # In p2tr, the least significant bit is the parity bit of the output public key's y-coordinate, which can be
        # either 0 or 1. In p2mr, which has no internal key/key path cost, this bit is always 1.
        self.prefix = 0xc0 + 1
        self.addr = pabtc.core.Address.p2mr(root)

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.r, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.r.script)
            e.witness = [
                pabtc.core.PriKey(4).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                pabtc.core.PriKey(3).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                mast.r.script,
                bytearray([self.prefix]) + mast.l.hash,
            ]
