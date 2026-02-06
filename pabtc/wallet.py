import abc
import json
import pabtc.core
import pabtc.denomination
import pabtc.rpc
import requests
import typing


class Analyzer:
    # Analyzer is a simple transaction analyzer to reject transactions that are obviously wrong.
    def __init__(self, tx: pabtc.core.Transaction) -> None:
        self.tx = tx

    def analyze_mining_fee(self) -> None:
        # Make sure the transaction fee is less than 50 satoshi per byte. An excessive fee, also called an absurd fee,
        # is any fee rate that's significantly higher than the amount that fee rate estimators currently expect is
        # necessary to get a transaction confirmed in the next block.
        sender_value = 0
        output_value = 0
        for e in self.tx.vin:
            o = e.out_point.load()
            sender_value += o.value
        for e in self.tx.vout:
            output_value += e.value
        assert sender_value - output_value <= self.tx.vbytes() * 50

    def analyze(self) -> None:
        self.analyze_mining_fee()


class Utxo:
    # Utxo stands for unspent transaction output. It represents an unspent output that can be used as an input in a new
    # transaction.
    def __init__(self, out_point: pabtc.core.OutPoint, out: pabtc.core.TxOut) -> None:
        self.out_point = out_point
        self.out = out

    def __eq__(self, other) -> bool:
        return all([
            self.out_point == other.out_point,
            self.out == other.out,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'out_point': self.out_point.json(),
            'out': self.out.json(),
        }


class SearcherCore:
    # Searcher provides the functionality to list unspent transaction outputs (utxo). To use this implementation, make
    # sure the address you want to query has been imported into your bitcoin core wallet.
    def __init__(self) -> None:
        pass

    def unspent(self, addr: str) -> typing.List[Utxo]:
        r = []
        for e in pabtc.rpc.list_unspent([addr]):
            out_point = pabtc.core.OutPoint(bytearray.fromhex(e['txid'])[::-1], e['vout'])
            script_pubkey = bytearray.fromhex(e['scriptPubKey'])
            amount = e['amount'] * pabtc.denomination.bitcoin
            amount = int(amount.to_integral_exact())
            utxo = Utxo(out_point, pabtc.core.TxOut(amount, script_pubkey))
            r.append(utxo)
        return r


class SearcherMempoolSpace:
    # Searcher provides the functionality to list unspent transaction outputs (utxo). Here we use the public API
    # provided by mempool for querying utxo.
    def __init__(self, net: str) -> None:
        assert net in ['mainnet', 'testnet']
        self.net = net

    def request(self, addr: str) -> str:
        if self.net == 'mainnet':
            return f'https://mempool.space/api/address/{addr}/utxo'
        if self.net == 'testnet':
            return f'https://mempool.space/testnet/api/address/{addr}/utxo'
        raise Exception('unreachable')

    def unspent(self, addr: str) -> typing.List[Utxo]:
        r = []
        for e in requests.get(self.request(addr)).json():
            out_point = pabtc.core.OutPoint(bytearray.fromhex(e['txid'])[::-1], e['vout'])
            # Mempool's api does not provide script_pubkey, so we have to infer it from the address.
            script_pubkey = pabtc.core.ScriptPubKey.address(addr)
            amount = e['value']
            utxo = Utxo(out_point, pabtc.core.TxOut(amount, script_pubkey))
            r.append(utxo)
        return r


class Searcher:
    # Searcher provides the functionality to list unspent transaction outputs (utxo).
    def __init__(self) -> None:
        pass

    def unspent(self, addr: str) -> typing.List[Utxo]:
        if pabtc.config.current == pabtc.config.develop:
            return SearcherCore().unspent(addr)
        if pabtc.config.current == pabtc.config.mainnet:
            return SearcherMempoolSpace('mainnet').unspent(addr)
        if pabtc.config.current == pabtc.config.testnet:
            return SearcherMempoolSpace('testnet').unspent(addr)
        raise Exception('unreachable')


class Signer(abc.ABC):
    # Signer provides the functionality to sign a transaction.

    @abc.abstractmethod
    def __init__(self) -> None:
        self.script: bytearray
        self.addr: str

    def json(self) -> typing.Dict:
        return {}

    @abc.abstractmethod
    def sign(self, tx: pabtc.core.Transaction) -> None:
        # Sign the transaction in place.
        pass


class Signerp2pkh(Signer):
    def __init__(self, prikey: pabtc.core.PriKey) -> None:
        self.prikey = prikey
        self.pubkey = self.prikey.pubkey()
        self.script = pabtc.core.ScriptPubKey.p2pkh(self.pubkey.hash())
        self.addr = pabtc.core.Address.p2pkh(self.pubkey.hash())

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'script': self.script.hex(),
            'addr': self.addr,
        }

    def sign(self, tx: pabtc.core.Transaction) -> None:
        for i, e in enumerate(tx.vin):
            m = tx.digest_legacy(i, pabtc.core.sighash_all, self.script)
            s = self.prikey.sign_ecdsa_der(m)
            s.append(pabtc.core.sighash_all)
            e.script_sig = pabtc.core.ScriptSig.p2pkh(s, self.pubkey)


class Signerp2shp2ms(Signer):
    def __init__(self, prikey: typing.List[pabtc.core.PriKey], pubkey: typing.List[pabtc.core.PubKey]) -> None:
        self.prikey = prikey
        self.pubkey = pubkey
        self.redeem = pabtc.core.ScriptPubKey.p2ms(len(prikey), pubkey)
        self.redeem_hash = pabtc.core.hash160(self.redeem)
        self.script = pabtc.core.ScriptPubKey.p2sh(self.redeem_hash)
        self.addr = pabtc.core.Address.p2sh(self.redeem_hash)

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'prikey': [e.json() for e in self.prikey],
            'pubkey': [e.json() for e in self.pubkey],
            'redeem': self.redeem.hex(),
            'script': self.script.hex(),
            'addr': self.addr,
        }

    def sign(self, tx: pabtc.core.Transaction) -> None:
        for i, e in enumerate(tx.vin):
            sig = []
            for prikey in self.prikey:
                s = prikey.sign_ecdsa_der(tx.digest_legacy(i, pabtc.core.sighash_all, self.redeem))
                s.append(pabtc.core.sighash_all)
                sig.append(s)
            e.script_sig = pabtc.core.ScriptSig.p2sh_p2ms(sig, len(self.prikey), self.pubkey)


class Signerp2shp2wpkh(Signer):
    def __init__(self, prikey: pabtc.core.PriKey) -> None:
        self.prikey = prikey
        self.pubkey = prikey.pubkey()
        self.script = pabtc.core.ScriptPubKey.p2sh_p2wpkh(self.pubkey.hash())
        self.addr = pabtc.core.Address.p2sh_p2wpkh(self.pubkey.hash())

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'script': self.script.hex(),
            'addr': self.addr,
        }

    def sign(self, tx: pabtc.core.Transaction) -> None:
        # See: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh-nested-in-bip16-p2sh
        for i, e in enumerate(tx.vin):
            e.script_sig = pabtc.core.ScriptSig.p2sh_p2wpkh(self.pubkey.hash())
            m = tx.digest_segwit_v0(i, pabtc.core.sighash_all, pabtc.core.ScriptPubKey.p2pkh(self.pubkey.hash()))
            s = self.prikey.sign_ecdsa_der(m)
            s.append(pabtc.core.sighash_all)
            e.witness = [s, self.pubkey.sec()]


class Signerp2wpkh(Signer):
    def __init__(self, prikey: pabtc.core.PriKey) -> None:
        self.prikey = prikey
        self.pubkey = prikey.pubkey()
        self.script = pabtc.core.ScriptPubKey.p2wpkh(self.pubkey.hash())
        self.addr = pabtc.core.Address.p2wpkh(self.pubkey.hash())

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'script': self.script.hex(),
            'addr': self.addr,
        }

    def sign(self, tx: pabtc.core.Transaction) -> None:
        # See: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v0(i, pabtc.core.sighash_all, pabtc.core.ScriptPubKey.p2pkh(self.pubkey.hash()))
            s = self.prikey.sign_ecdsa_der(m)
            s.append(pabtc.core.sighash_all)
            e.witness = [s, self.pubkey.sec()]


class Signerp2tr(Signer):
    def __init__(self, prikey: pabtc.core.PriKey, merkle: bytearray) -> None:
        self.prikey = prikey
        self.pubkey = prikey.pubkey()
        self.merkle = merkle
        self.prikey_tweak = pabtc.core.PriKey.fr_decode(pabtc.taproot.prikey_tweak(self.prikey.fr(), self.merkle))
        self.pubkey_tweak = pabtc.core.PubKey.pt_decode(pabtc.taproot.pubkey_tweak(self.pubkey.pt(), merkle))
        self.script = pabtc.core.ScriptPubKey.p2tr(bytearray(self.pubkey_tweak.x.to_bytes(32)))
        self.addr = pabtc.core.Address.p2tr(bytearray(self.pubkey_tweak.x.to_bytes(32)))

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def json(self) -> typing.Dict:
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'merkle': self.merkle.hex(),
            'script': self.script.hex(),
            'addr': self.addr,
        }

    def sign(self, tx: pabtc.core.Transaction) -> None:
        # See: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
        for i, e in enumerate(tx.vin):
            m = tx.digest_segwit_v1(i, pabtc.core.sighash_all, bytearray())
            s = self.prikey_tweak.sign_schnorr(m) + bytearray([pabtc.core.sighash_all])
            e.witness = [s]


class Wallet:
    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.script = self.signer.script
        self.search = Searcher()
        self.addr = self.signer.addr

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def balance(self) -> int:
        return sum([e.out.value for e in self.unspent()])

    def json(self) -> typing.Dict:
        return self.signer.json()

    def transfer(self, script: bytearray, value: int) -> bytearray:
        sender_value = 0
        accept_value = value
        accept_script = script
        change_value = 0
        change_script = self.script
        fr = pabtc.rpc.estimate_smart_fee(6)['feerate'] * pabtc.denomination.bitcoin
        fr = int(fr.to_integral_exact()) // 1000
        tx = pabtc.core.Transaction(2, [], [], 0)
        tx.vout.append(pabtc.core.TxOut(accept_value, accept_script))
        tx.vout.append(pabtc.core.TxOut(change_value, change_script))
        for utxo in self.unspent():
            txin = pabtc.core.TxIn(utxo.out_point, bytearray(), 0xffffffff, [])
            tx.vin.append(txin)
            sender_value += utxo.out.value
            change_value = sender_value - accept_value - tx.vbytes() * fr
            # How was the dust limit of 546 satoshis was chosen?
            # See: https://bitcoin.stackexchange.com/questions/86068
            if change_value >= 546:
                break
        assert change_value >= 546
        tx.vout[1].value = change_value
        self.signer.sign(tx)
        Analyzer(tx).analyze()
        txid = bytearray.fromhex(pabtc.rpc.send_raw_transaction(tx.serialize().hex()))[::-1]
        return txid

    def transfer_all(self, script: bytearray) -> bytearray:
        sender_value = 0
        accept_value = 0
        accept_script = script
        fr = pabtc.rpc.estimate_smart_fee(6)['feerate'] * pabtc.denomination.bitcoin
        fr = int(fr.to_integral_exact()) // 1000
        tx = pabtc.core.Transaction(2, [], [], 0)
        tx.vout.append(pabtc.core.TxOut(accept_value, accept_script))
        for utxo in self.unspent():
            txin = pabtc.core.TxIn(utxo.out_point, bytearray(), 0xffffffff, [])
            tx.vin.append(txin)
            sender_value += utxo.out.value
        accept_value = sender_value - tx.vbytes() * fr
        assert accept_value >= 546
        tx.vout[0].value = accept_value
        self.signer.sign(tx)
        Analyzer(tx).analyze()
        txid = bytearray.fromhex(pabtc.rpc.send_raw_transaction(tx.serialize().hex()))[::-1]
        return txid

    def unspent(self) -> typing.List[Utxo]:
        return self.search.unspent(self.addr)
