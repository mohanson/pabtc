import pabtc

# This example shows how to create a P2TR script with two unlock conditions: p2pk and p2ms.


# Here created two scripts, one of which is a p2pk script, which requires that it can only be unlocked by private key 2,
# and the other is an 2-of-2 multisig script.
mast = pabtc.core.TapBranch(
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2pk(pabtc.core.PriKey(2).pubkey())),
    pabtc.core.TapLeaf(pabtc.core.TapScript.p2ms(2, [pabtc.core.PriKey(3).pubkey(), pabtc.core.PriKey(4).pubkey()])),
)


class Signerp2trp2pk(pabtc.wallet.Signer):
    def __init__(self, pubkey: pabtc.core.PubKey) -> None:
        self.pubkey = pubkey
        p2tr_pubkey = bytearray(pabtc.taproot.pubkey_tweak(pubkey.pt(), mast.hash).x.n.to_bytes(32))
        self.addr = pabtc.core.Address.p2tr(p2tr_pubkey)
        self.script = pabtc.core.ScriptPubKey.address(self.addr)
        output_pubkey_byte = bytearray(
            [0x02]) + pabtc.bech32.decode_segwit_addr(pabtc.config.current.prefix.bech32, 1, self.addr)
        output_pubkey = pabtc.core.PubKey.sec_decode(output_pubkey_byte)
        # Control byte with leaf version and parity bit.
        if output_pubkey.y & 1:
            self.prefix = 0xc1
        else:
            self.prefix = 0xc0

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.l, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.l.script)
            s = pabtc.core.PriKey(2).sign_schnorr(m) + bytearray([pabtc.core.sighash_all])
            e.witness = [
                s,
                mast.l.script,
                bytearray([self.prefix]) + self.pubkey.sec()[1:] + mast.r.hash,
            ]


class Signerp2trp2ms(pabtc.wallet.Signer):
    def __init__(self, pubkey: pabtc.core.PubKey) -> None:
        self.pubkey = pubkey
        p2tr_pubkey = bytearray(pabtc.taproot.pubkey_tweak(pubkey.pt(), mast.hash).x.n.to_bytes(32))
        self.addr = pabtc.core.Address.p2tr(p2tr_pubkey)
        self.script = pabtc.core.ScriptPubKey.address(self.addr)
        output_pubkey_byte = bytearray(
            [0x02]) + pabtc.bech32.decode_segwit_addr(pabtc.config.current.prefix.bech32, 1, self.addr)
        output_pubkey = pabtc.core.PubKey.sec_decode(output_pubkey_byte)
        # Control byte with leaf version and parity bit.
        if output_pubkey.y & 1:
            self.prefix = 0xc1
        else:
            self.prefix = 0xc0

    def sign(self, tx: pabtc.core.Transaction) -> None:
        assert isinstance(mast.r, pabtc.core.TapLeaf)
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, mast.r.script)
            e.witness = [
                pabtc.core.PriKey(4).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                pabtc.core.PriKey(3).sign_schnorr(m) + bytearray([pabtc.core.sighash_all]),
                mast.r.script,
                bytearray([self.prefix]) + self.pubkey.sec()[1:] + mast.l.hash,
            ]


mate = pabtc.wallet.Wallet(pabtc.wallet.Signerp2pkh(1))
pabtc.rpc.generate_to_address(10, mate.addr)

user_p2tr_signer = pabtc.wallet.Signerp2tr(1, mast.hash)
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
user_p2pk = pabtc.wallet.Wallet(Signerp2trp2pk(user_p2tr_signer.pubkey))
print('main: spending by script path p2pk')
user_p2pk.transfer_all(mate.script)
assert user_p2tr.balance() == 0
print('main: spending by script path p2pk done')

# Spending by script path: pay to 2-of-2 multisig script.
mate.transfer(user_p2tr.script, 1 * pabtc.denomination.bitcoin)
assert user_p2tr.balance() == pabtc.denomination.bitcoin
user_p2ms = pabtc.wallet.Wallet(Signerp2trp2ms(user_p2tr_signer.pubkey))
print('main: spending by script path p2ms')
user_p2ms.transfer_all(mate.script)
assert user_p2tr.balance() == 0
print('main: spending by script path p2ms done')
