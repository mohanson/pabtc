import itertools
import pabtc


def test_wallet_transfer():
    pabtc.config.current = pabtc.config.develop
    user_list = [
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2pkh(pabtc.core.PriKey(1))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2shp2ms(
            [pabtc.core.PriKey(e) for e in [1, 2]],
            [pabtc.core.PriKey(e).pubkey() for e in [1, 2]]),
        ),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2shp2wpkh(pabtc.core.PriKey(1))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2wpkh(pabtc.core.PriKey(1))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2tr(pabtc.core.PriKey(1), bytearray())),
    ]
    mate_list = [
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2pkh(pabtc.core.PriKey(2))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2shp2ms(
            [pabtc.core.PriKey(e) for e in [2, 1]],
            [pabtc.core.PriKey(e).pubkey() for e in [2, 1]]),
        ),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2shp2wpkh(pabtc.core.PriKey(2))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2wpkh(pabtc.core.PriKey(2))),
        pabtc.wallet.Wallet(pabtc.wallet.Signerp2tr(pabtc.core.PriKey(2), bytearray())),
    ]
    for user, mate in itertools.product(user_list, mate_list):
        value = pabtc.denomination.bitcoin
        value_old = mate.balance()
        txid = user.transfer(mate.script, value)
        pabtc.rpc.wait(txid[::-1].hex())
        value_new = mate.balance()
        assert value_new - value_old == value
        value_old = value_new
        txid = user.transfer(mate.script, value)
        pabtc.rpc.wait(txid[::-1].hex())
        value_new = mate.balance()
        assert value_new - value_old == value
        pabtc.rpc.generate_to_address(6, user.addr)
        txid = mate.transfer_all(user.script)
        pabtc.rpc.wait(txid[::-1].hex())
        assert mate.balance() == 0
