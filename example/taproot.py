import pabtc

# This example shows how to create a P2TR script with two unlock conditions: p2pk and p2ms.


# Here created two scripts, one of which is a p2pk script, which requires that it can only be unlocked by private key 2,
# and the other is an 2-of-2 multisig script.
prikey = pabtc.core.PriKey(1)
pubkey = prikey.pubkey()
mast = pabtc.core.TapBranch(
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2pk(pabtc.core.PriKey(2).pubkey())),
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2ms(2, [pabtc.core.PriKey(3).pubkey(), pabtc.core.PriKey(4).pubkey()])),
)
prikey_tweak = pabtc.taproot.prikey_tweak(prikey.fr(), mast.hash)
pubkey_tweak = pabtc.taproot.pubkey_tweak(pubkey.pt(), mast.hash)
root = bytearray(pubkey_tweak.x.n.to_bytes(32))


class Signerp2trp2pk(pabtc.wallet.Signer):
    def __init__(self) -> None:
        self.script = pabtc.core.ScriptPubKey.p2tr(root)
        self.prefix = 0xc0 + (pubkey.y & 1)
        self.addr = pabtc.core.Address.p2tr(root)

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.l, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.l.script)
            e.witness = [
                pabtc.core.PriKey(2).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                mast.l.script,
                bytearray([self.prefix]) + pubkey.sec()[1:] + mast.r.hash,
            ]


class Signerp2trp2ms(pabtc.wallet.Signer):
    def __init__(self) -> None:
        self.script = pabtc.core.ScriptPubKey.p2tr(root)
        self.prefix = 0xc0 + (pubkey.y & 1)
        self.addr = pabtc.core.Address.p2tr(root)

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.r, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.r.script)
            e.witness = [
                pabtc.core.PriKey(4).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                pabtc.core.PriKey(3).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                mast.r.script,
                bytearray([self.prefix]) + pubkey.sec()[1:] + mast.l.hash,
            ]


mate = pabtc.wallet.Wallet(pabtc.wallet.Signerp2pkh(pabtc.core.PriKey(1)))
pabtc.rpc.generate_to_address(10, mate.addr)

user_p2tr_signer = pabtc.wallet.Signerp2tr(pabtc.core.PriKey(1), mast.hash)
user_p2tr = pabtc.wallet.Wallet(user_p2tr_signer)
pabtc.rpc.import_descriptors([{
    'desc': pabtc.rpc.get_descriptor_info(f'addr({user_p2tr.addr})')['descriptor'],
    'timestamp': 'now',
}])

# Spending by key path.
mate.transfer(user_p2tr.script, 1 * pabtc.denomination.bitcoin)
assert user_p2tr.balance() == pabtc.denomination.bitcoin
print('main: spending by key path')
user_p2tr.transfer_all(mate.script)
assert user_p2tr.balance() == 0
print('main: spending by key path done')

# Spending by script path: pay to public key.
mate.transfer(user_p2tr.script, 1 * pabtc.denomination.bitcoin)
assert user_p2tr.balance() == pabtc.denomination.bitcoin
user_p2pk = pabtc.wallet.Wallet(Signerp2trp2pk())
print('main: spending by script path p2pk')
user_p2pk.transfer_all(mate.script)
assert user_p2tr.balance() == 0
print('main: spending by script path p2pk done')

# Spending by script path: pay to 2-of-2 multisig script.
mate.transfer(user_p2tr.script, 1 * pabtc.denomination.bitcoin)
assert user_p2tr.balance() == pabtc.denomination.bitcoin
user_p2ms = pabtc.wallet.Wallet(Signerp2trp2ms())
print('main: spending by script path p2ms')
user_p2ms.transfer_all(mate.script)
assert user_p2tr.balance() == 0
print('main: spending by script path p2ms done')
