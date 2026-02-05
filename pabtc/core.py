import base64
import hashlib
import io
import itertools
import json
import math
import pabtc.base58
import pabtc.bech32
import pabtc.compact_size
import pabtc.config
import pabtc.denomination
import pabtc.der
import pabtc.ecdsa
import pabtc.opcode
import pabtc.ripemd160
import pabtc.rpc
import pabtc.schnorr
import pabtc.secp256k1
import secrets
import typing

sighash_default = 0x00
sighash_all = 0x01
sighash_none = 0x02
sighash_single = 0x03
sighash_anyone_can_pay = 0x80


def hash160(data: bytearray) -> bytearray:
    return bytearray(pabtc.ripemd160.ripemd160(bytearray(hashlib.sha256(data).digest())).digest())


def hash256(data: bytearray) -> bytearray:
    return bytearray(hashlib.sha256(hashlib.sha256(data).digest()).digest())


def hashtag(name: str, data: bytearray) -> bytearray:
    return pabtc.schnorr.hash(name, data)


def hashwsh(data: bytearray) -> bytearray:
    return bytearray(hashlib.sha256(data).digest())


class PriKey:
    # Bitcoin private key is an integer between 0 and n, where n is slightly smaller than 2**256.

    def __init__(self, n: int) -> None:
        self.n = n

    def __eq__(self, other) -> bool:
        return self.n == other.n

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def fr(self) -> pabtc.secp256k1.Fr:
        # Convert the private key to secp256k1 field representation.
        return pabtc.secp256k1.Fr(self.n)

    @classmethod
    def fr_decode(cls, data: pabtc.secp256k1.Fr) -> PriKey:
        # Convert the secp256k1 field representation to private key.
        return PriKey(data.n)

    def hex(self) -> str:
        # Convert the private key to hex representation.
        return self.n.to_bytes(32).hex()

    @classmethod
    def hex_decode(cls, data: str) -> PriKey:
        # Convert the hex representation to private key.
        return PriKey(int.from_bytes(bytearray.fromhex(data)))

    def json(self) -> typing.Dict:
        # Convert the private key to json representation.
        return {
            'n': f'{self.n:064x}',
        }

    def pubkey(self) -> PubKey:
        # Get the ecdsa public key corresponding to the private key.
        pubkey = pabtc.secp256k1.G * pabtc.secp256k1.Fr(self.n)
        return PubKey(pubkey.x.n, pubkey.y.n)

    @classmethod
    def random(cls) -> PriKey:
        return PriKey(max(1, secrets.randbelow(pabtc.secp256k1.N)))

    def sign_ecdsa(self, data: bytearray) -> typing.Tuple[pabtc.secp256k1.Fr, pabtc.secp256k1.Fr, int]:
        # Sign a 32-byte data segment, returns the signature.
        assert len(data) == 32
        m = pabtc.secp256k1.Fr(int.from_bytes(data))
        for _ in itertools.repeat(0):
            r, s, v = pabtc.ecdsa.sign(pabtc.secp256k1.Fr(self.n), m)
            # We require that the S value inside ECDSA signatures is at most the curve order divided by 2 (essentially
            # restricting this value to its lower half range).
            # See: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
            if s.n * 2 >= pabtc.secp256k1.N:
                s = -s
                v ^= 1
            return r, s, v
        raise Exception('unreachable')

    def sign_ecdsa_der(self, data: bytearray) -> bytearray:
        # Sign a 32-byte data segment, returns the signature in der format.
        r, s, _ = self.sign_ecdsa(data)
        return pabtc.der.encode(r, s)

    def sign_schnorr(self, data: bytearray) -> bytearray:
        # Sign a 32-byte data segment, returns the signature.
        assert len(data) == 32
        m = pabtc.secp256k1.Fr(int.from_bytes(data))
        r, s = pabtc.schnorr.sign(pabtc.secp256k1.Fr(self.n), m)
        return bytearray(r.x.n.to_bytes(32) + s.n.to_bytes(32))

    def wif(self) -> str:
        # Convert the private key to wallet import format. This is the format supported by most third-party wallets.
        # See https://en.bitcoin.it/wiki/Wallet_import_format
        data = bytearray()
        data.append(pabtc.config.current.prefix.base58.wif)
        data.extend(self.n.to_bytes(32))
        # Also add a 0x01 byte at the end if the private key will correspond to a compressed public key.
        data.append(0x01)
        checksum = hash256(data)[:4]
        data.extend(checksum)
        return pabtc.base58.encode(data)

    @classmethod
    def wif_decode(cls, data: str) -> PriKey:
        # Convert the wallet import format to private key. This is the format supported by most third-party wallets.
        b = pabtc.base58.decode(data)
        assert b[0] == pabtc.config.current.prefix.base58.wif
        assert hash256(b[:-4])[:4] == b[-4:]
        return PriKey(int.from_bytes(b[1:33]))


class PubKey:
    # Bitcoin public key is created via elliptic curve multiplication.

    def __init__(self, x: int, y: int) -> None:
        # The public key must be on the curve.
        _ = pabtc.secp256k1.Pt(pabtc.secp256k1.Fq(x), pabtc.secp256k1.Fq(y))
        self.x = x
        self.y = y

    def __eq__(self, other) -> bool:
        return all([
            self.x == other.x,
            self.y == other.y,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def hash(self) -> bytearray:
        # Get the hash160 of the public key.
        return hash160(self.sec())

    def json(self) -> typing.Dict:
        # Convert the public key to json representation.
        return {
            'x': f'{self.x:064x}',
            'y': f'{self.y:064x}'
        }

    def pt(self) -> pabtc.secp256k1.Pt:
        # Convert the public key to secp256k1 point.
        return pabtc.secp256k1.Pt(pabtc.secp256k1.Fq(self.x), pabtc.secp256k1.Fq(self.y))

    @classmethod
    def pt_decode(cls, data: pabtc.secp256k1.Pt) -> PubKey:
        # Convert the secp256k1 point to public key.
        return PubKey(data.x.n, data.y.n)

    def sec(self) -> bytearray:
        # Convert the public key to standards for efficient cryptography representation. Elsewhere, it is referred to
        # as the compressed format of the public key.
        r = bytearray()
        if self.y & 1 == 0:
            r.append(0x02)
        else:
            r.append(0x03)
        r.extend(self.x.to_bytes(32))
        return r

    @classmethod
    def sec_decode(cls, data: bytearray) -> PubKey:
        # Convert the standards for efficient cryptography representation to public key.
        p = data[0]
        assert p in [0x02, 0x03, 0x04]
        x = int.from_bytes(data[1:33])
        if p == 0x04:
            y = int.from_bytes(data[33:65])
        else:
            y_x_y = x * x * x + pabtc.secp256k1.A.n * x + pabtc.secp256k1.B.n
            y = pow(y_x_y, (pabtc.secp256k1.P + 1) // 4, pabtc.secp256k1.P)
            if y & 1 != p - 2:
                y = -y % pabtc.secp256k1.P
        return PubKey(x, y)


class ScriptPubKey:
    # The Script pubkey is the locking code for an output. It's made up of script, which is a mini programming language
    # that allows you to place different types of locks on your outputs.

    @classmethod
    def p2pk(cls, pubkey: PubKey) -> bytearray:
        data = bytearray()
        data.extend(pabtc.opcode.op_pushdata(pubkey.sec()))
        data.append(pabtc.opcode.op_checksig)
        return data

    @classmethod
    def p2pkh(cls, pubkey_hash: bytearray) -> bytearray:
        assert len(pubkey_hash) == 20
        data = bytearray()
        data.append(pabtc.opcode.op_dup)
        data.append(pabtc.opcode.op_hash160)
        data.extend(pabtc.opcode.op_pushdata(pubkey_hash))
        data.append(pabtc.opcode.op_equalverify)
        data.append(pabtc.opcode.op_checksig)
        return data

    @classmethod
    def p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> bytearray:
        data = bytearray()
        data.append(pabtc.opcode.op_n(m))
        for e in pubkey:
            data.extend(pabtc.opcode.op_pushdata(e.sec()))
        data.append(pabtc.opcode.op_n(len(pubkey)))
        data.append(pabtc.opcode.op_checkmultisig)
        return data

    @classmethod
    def p2sh(cls, redeem_hash: bytearray) -> bytearray:
        assert len(redeem_hash) == 20
        data = bytearray()
        data.append(pabtc.opcode.op_hash160)
        data.extend(pabtc.opcode.op_pushdata(redeem_hash))
        data.append(pabtc.opcode.op_equal)
        return data

    @classmethod
    def p2sh_p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> bytearray:
        redeem = cls.p2ms(m, pubkey)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2sh_p2wpkh(cls, pubkey_hash: bytearray) -> bytearray:
        assert len(pubkey_hash) == 20
        redeem = cls.p2wpkh(pubkey_hash)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2sh_p2wsh(cls, redeem_hash: bytearray) -> bytearray:
        assert len(redeem_hash) == 32
        redeem = cls.p2wsh(redeem_hash)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2wpkh(cls, pubkey_hash: bytearray) -> bytearray:
        assert len(pubkey_hash) == 20
        data = bytearray()
        data.append(pabtc.opcode.op_0)
        data.extend(pabtc.opcode.op_pushdata(pubkey_hash))
        return data

    @classmethod
    def p2wsh(cls, redeem_hash: bytearray) -> bytearray:
        # The script hash within a p2wsh is a single sha-256. It is not a double sha-256 hash (i.e. hash256) as is
        # commonly used everywhere else in bitcoin, nor is it the hash160 of a script like in p2sh.
        assert len(redeem_hash) == 32
        data = bytearray()
        data.append(pabtc.opcode.op_0)
        data.extend(pabtc.opcode.op_pushdata(redeem_hash))
        return data

    @classmethod
    def p2wsh_p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> bytearray:
        redeem = cls.p2ms(m, pubkey)
        redeem_hash = hashwsh(redeem)
        return cls.p2wsh(redeem_hash)

    @classmethod
    def p2tr(cls, root: bytearray) -> bytearray:
        assert len(root) == 32
        data = bytearray()
        data.append(pabtc.opcode.op_1)
        data.extend(pabtc.opcode.op_pushdata(root))
        return data

    @classmethod
    def address(cls, address: str) -> bytearray:
        if address.startswith(pabtc.config.current.prefix.bech32):
            if address[len(pabtc.config.current.prefix.bech32) + 1] == 'q':
                data = pabtc.bech32.decode_segwit_addr(pabtc.config.current.prefix.bech32, 0, address)
                if len(data) == 20:
                    return cls.p2wpkh(data)
                if len(data) == 32:
                    return cls.p2wsh(data)
            if address[len(pabtc.config.current.prefix.bech32) + 1] == 'p':
                data = pabtc.bech32.decode_segwit_addr(pabtc.config.current.prefix.bech32, 1, address)
                return cls.p2tr(data)
        data = pabtc.base58.decode(address)
        if data[0] == pabtc.config.current.prefix.base58.p2pkh:
            assert pabtc.core.hash256(data[0x00:0x15])[:4] == data[0x15:0x19]
            return ScriptPubKey.p2pkh(data[0x01:0x15])
        if data[0] == pabtc.config.current.prefix.base58.p2sh:
            assert pabtc.core.hash256(data[0x00:0x15])[:4] == data[0x15:0x19]
            return ScriptPubKey.p2sh(data[0x01:0x15])
        raise Exception('unreachable')


class ScriptSig:
    # A script sig provides the unlocking code for a previous output. Each output in a transaction has a locking code
    # placed on it. So when you come to select one as an input in a future transaction, you need to supply an unlocking
    # code so that it can be spent. This locking/unlocking code uses a mini-programming language called script.

    @classmethod
    def p2pk(cls, sig: bytearray) -> bytearray:
        data = bytearray()
        data.extend(pabtc.opcode.op_pushdata(sig))
        return data

    @classmethod
    def p2pkh(cls, sig: bytearray, pubkey: PubKey) -> bytearray:
        data = bytearray()
        data.extend(pabtc.opcode.op_pushdata(sig))
        data.extend(pabtc.opcode.op_pushdata(pubkey.sec()))
        return data

    @classmethod
    def p2ms(cls, sig: typing.List[bytearray]) -> bytearray:
        data = bytearray()
        # Due to a bug in the original bitcoin implementation, an extra op_0 is required.
        data.append(pabtc.opcode.op_0)
        for e in sig:
            data.extend(pabtc.opcode.op_pushdata(e))
        return data

    @classmethod
    def p2sh(cls, script: bytearray, redeem: bytearray) -> bytearray:
        data = bytearray()
        # Script is the unlocking code required to unlock the upcoming redeem script.
        data.extend(script)
        data.extend(pabtc.opcode.op_pushdata(redeem))
        return data

    @classmethod
    def p2sh_p2ms(cls, sig: typing.List[bytearray], m: int, pubkey: typing.List[PubKey]) -> bytearray:
        script = cls.p2ms(sig)
        redeem = ScriptPubKey.p2ms(m, pubkey)
        return cls.p2sh(script, redeem)

    @classmethod
    def p2sh_p2wpkh(cls, pubkey_hash: bytearray) -> bytearray:
        assert len(pubkey_hash) == 20
        script = bytearray()
        redeem = ScriptPubKey.p2wpkh(pubkey_hash)
        return cls.p2sh(script, redeem)

    @classmethod
    def p2sh_p2wsh(cls, redeem_hash: bytearray) -> bytearray:
        assert len(redeem_hash) == 32
        script = bytearray()
        redeem = ScriptPubKey.p2wsh(redeem_hash)
        return cls.p2sh(script, redeem)


class Address:
    # Bitcoin address is a string that represents a destination for a bitcoin payment.

    @classmethod
    def p2pkh(cls, pubkey_hash: bytearray) -> str:
        assert len(pubkey_hash) == 20
        data = bytearray([pabtc.config.current.prefix.base58.p2pkh]) + pubkey_hash
        chk4 = hash256(data)[:4]
        return pabtc.base58.encode(data + chk4)

    @classmethod
    def p2sh(cls, redeem_hash: bytearray) -> str:
        assert len(redeem_hash) == 20
        data = bytearray([pabtc.config.current.prefix.base58.p2sh]) + redeem_hash
        chk4 = hash256(data)[:4]
        return pabtc.base58.encode(data + chk4)

    @classmethod
    def p2sh_p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> str:
        redeem = ScriptPubKey.p2ms(m, pubkey)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2sh_p2wpkh(cls, pubkey_hash: bytearray) -> str:
        assert len(pubkey_hash) == 20
        redeem = ScriptPubKey.p2wpkh(pubkey_hash)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2sh_p2wsh(cls, redeem_hash: bytearray) -> str:
        assert len(redeem_hash) == 32
        redeem = ScriptPubKey.p2wsh(redeem_hash)
        redeem_hash = hash160(redeem)
        return cls.p2sh(redeem_hash)

    @classmethod
    def p2wpkh(cls, pubkey_hash: bytearray) -> str:
        assert len(pubkey_hash) == 20
        return pabtc.bech32.encode_segwit_addr(pabtc.config.current.prefix.bech32, 0, pubkey_hash)

    @classmethod
    def p2wsh(cls, redeem_hash: bytearray) -> str:
        assert len(redeem_hash) == 32
        return pabtc.bech32.encode_segwit_addr(pabtc.config.current.prefix.bech32, 0, redeem_hash)

    @classmethod
    def p2wsh_p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> str:
        redeem = ScriptPubKey.p2ms(m, pubkey)
        redeem_hash = hashwsh(redeem)
        return cls.p2wsh(redeem_hash)

    @classmethod
    def p2tr(cls, root: bytearray) -> str:
        assert len(root) == 32
        return pabtc.bech32.encode_segwit_addr(pabtc.config.current.prefix.bech32, 1, root)

    @classmethod
    def script_pubkey(cls, script_pubkey: bytearray) -> str:
        if len(script_pubkey) == 25 and all([
            script_pubkey[0x00] == pabtc.opcode.op_dup,
            script_pubkey[0x01] == pabtc.opcode.op_hash160,
            script_pubkey[0x02] == pabtc.opcode.op_data_20,
            script_pubkey[0x17] == pabtc.opcode.op_equalverify,
            script_pubkey[0x18] == pabtc.opcode.op_checksig,
        ]):
            return cls.p2pkh(script_pubkey[0x03:0x17])
        if len(script_pubkey) == 23 and all([
            script_pubkey[0x00] == pabtc.opcode.op_hash160,
            script_pubkey[0x01] == pabtc.opcode.op_data_20,
            script_pubkey[0x16] == pabtc.opcode.op_equal,
        ]):
            return cls.p2sh(script_pubkey[0x02:0x16])
        if len(script_pubkey) == 22 and all([
            script_pubkey[0x00] == pabtc.opcode.op_0,
            script_pubkey[0x01] == pabtc.opcode.op_data_20,
        ]):
            return cls.p2wpkh(script_pubkey[0x02:0x16])
        if len(script_pubkey) == 34 and all([
            script_pubkey[0x00] == pabtc.opcode.op_0,
            script_pubkey[0x01] == pabtc.opcode.op_data_32,
        ]):
            return cls.p2wsh(script_pubkey[0x02:0x22])
        if len(script_pubkey) == 34 and all([
            script_pubkey[0x00] == pabtc.opcode.op_1,
            script_pubkey[0x01] == pabtc.opcode.op_data_32,
        ]):
            return cls.p2tr(script_pubkey[0x02:0x22])
        raise Exception('unreachable')


class Difficulty:
    # Difficulty: See https://en.bitcoin.it/wiki/Difficulty.

    @classmethod
    def target(cls, bits: int) -> int:
        assert bits >= 0x00
        assert bits <= 0xffffffff
        base = bits & 0xffffff
        # Since targets are never negative in practice, however, this means the largest legal value for the lower 24 bits
        # is 0x7fffff. Additionally, 0x008000 is the smallest legal value for the lower 24 bits since targets are always
        # stored with the lowest possible exponent.
        assert base >= 0x008000
        assert base <= 0x7fffff
        exps = bits >> 24
        if exps <= 3:
            return base >> (8 * (3 - exps))
        else:
            return base << (8 * (exps - 3))

    @classmethod
    def b(cls, bits: int) -> float:
        # Returns the bdiff. The formula of difficulty is difficulty_1_target / current_target (target is a 256 bit
        # number). The highest possible target (difficulty 1) is defined as 0x1d00ffff.
        return 0x00000000ffff0000000000000000000000000000000000000000000000000000 / cls.target(bits)

    @classmethod
    def p(cls, bits: int) -> float:
        # Returns the pdiff.
        return 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff / cls.target(bits)

    @classmethod
    def hash_rate(cls, bits: int) -> float:
        # Get network hash rate results in a given difficulty. The result is in hashes per second.
        return cls.p(bits) * 2**32 / 600


class TapBranch:
    def __init__(self, l: TapBranch | TapLeaf, r: TapBranch | TapLeaf) -> None:
        self.l = l
        self.r = r
        self.hash = hashtag('TapBranch', bytearray().join(sorted([l.hash, r.hash])))


class TapLeaf:
    def __init__(self, script: bytearray) -> None:
        self.script = script
        data = bytearray()
        # Leaf version: currently, only 0xc0 is defined.
        data.append(0xc0)
        data.extend(pabtc.compact_size.encode(len(script)))
        data.extend(script)
        self.hash = hashtag('TapLeaf', data)


class TapScript:
    # The custom locking scripts inside p2tr use a slightly modified version of script.

    @classmethod
    def p2pk(cls, pubkey: PubKey) -> bytearray:
        data = bytearray()
        data.extend(pabtc.opcode.op_pushdata(bytearray(pubkey.x.to_bytes(32))))
        data.append(pabtc.opcode.op_checksig)
        return data

    @classmethod
    def p2ms(cls, m: int, pubkey: typing.List[PubKey]) -> bytearray:
        data = bytearray()
        data.extend(pabtc.opcode.op_pushdata(bytearray(pubkey[0].x.to_bytes(32))))
        data.append(pabtc.opcode.op_checksig)
        for e in pubkey[1:]:
            data.extend(pabtc.opcode.op_pushdata(bytearray(e.x.to_bytes(32))))
            data.append(pabtc.opcode.op_checksigadd)
        data.append(pabtc.opcode.op_n(m))
        data.append(pabtc.opcode.op_equal)
        return data


class HashType:
    # HashType represents the signature hash type used in bitcoin transactions to control which parts of the
    # transaction are signed. It determines what can be modified without invalidating the signature.
    # See: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    # See: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

    def __init__(self, n: int) -> None:
        assert n in [
            sighash_default,                          # 0x00: Default for Taproot (equivalent to ALL)
            sighash_all,                              # 0x01: Sign all inputs and outputs
            sighash_none,                             # 0x02: Sign all inputs, no outputs
            sighash_single,                           # 0x03: Sign all inputs, only the output at the same index
            sighash_anyone_can_pay | sighash_all,     # 0x81: Sign only this input, all outputs
            sighash_anyone_can_pay | sighash_none,    # 0x82: Sign only this input, no outputs
            sighash_anyone_can_pay | sighash_single,  # 0x83: Sign only this input, only corresponding output
        ]
        self.i = n & sighash_anyone_can_pay
        self.o = n & 0x3
        if n == sighash_default:
            self.i = sighash_all


class OutPoint:
    # A combination of a transaction hash and an index n into its vout.

    def __init__(self, txid: bytearray, vout: int) -> None:
        assert len(txid) == 32
        assert vout >= 0
        assert vout <= 0xffffffff
        self.txid = txid
        self.vout = vout

    def __eq__(self, other) -> bool:
        return all([
            self.txid == other.txid,
            self.vout == other.vout,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def copy(self) -> OutPoint:
        return OutPoint(self.txid.copy(), self.vout)

    def json(self) -> typing.Dict:
        return {
            'txid': self.txid.hex(),
            'vout': self.vout,
        }

    def load(self) -> TxOut:
        # Load the tx out referenced by this out point via rpc.
        rpcret = pabtc.rpc.get_tx_out(self.txid[::-1].hex(), self.vout)
        script_pubkey = bytearray.fromhex(rpcret['scriptPubKey']['hex'])
        amount = rpcret['value'] * pabtc.denomination.bitcoin
        amount = int(amount.to_integral_exact())
        return TxOut(amount, script_pubkey)


class TxIn:
    # An input of a transaction. It contains the location of the previous transaction's output that it claims and a
    # signature that matches the output's public key.

    def __init__(
        self,
        out_point: OutPoint,
        script_sig: bytearray,
        sequence: int,
        witness: typing.List[bytearray]
    ) -> None:
        assert sequence >= 0
        assert sequence <= 0xffffffff
        self.out_point = out_point
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness

    def __eq__(self, other) -> bool:
        return all([
            self.out_point == other.out_point,
            self.script_sig == other.script_sig,
            self.sequence == other.sequence,
            self.witness == other.witness,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def copy(self) -> TxIn:
        return TxIn(self.out_point.copy(), self.script_sig.copy(), self.sequence, [e.copy() for e in self.witness])

    def json(self) -> typing.Dict:
        return {
            'out_point': self.out_point.json(),
            'script_sig': self.script_sig.hex(),
            'sequence': self.sequence,
            'witness': [e.hex() for e in self.witness],
        }


class TxOut:
    # An output of a transaction. It contains the public key that the next input must be able to sign with to claim it.
    def __init__(self, value: int, script_pubkey: bytearray) -> None:
        assert value >= 0
        assert value <= 0xffffffffffffffff
        self.value = value
        self.script_pubkey = script_pubkey

    def __eq__(self, other) -> bool:
        return all([
            self.value == other.value,
            self.script_pubkey == other.script_pubkey,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def copy(self) -> TxOut:
        return TxOut(self.value, self.script_pubkey.copy())

    def json(self) -> typing.Dict:
        return {
            'value': self.value,
            'script_pubkey': self.script_pubkey.hex(),
        }


class Transaction:
    # Referring to the design of Bitcoin core.
    # See: https://github.com/bitcoin/bitcoin/blob/master/src/primitives/transaction.h

    def __init__(self, version: int, vin: typing.List[TxIn], vout: typing.List[TxOut], locktime: int) -> None:
        self.version = version
        self.vin = vin
        self.vout = vout
        self.locktime = locktime

    def __eq__(self, other) -> bool:
        return all([
            self.version == other.version,
            self.vin == other.vin,
            self.vout == other.vout,
            self.locktime == other.locktime,
        ])

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def copy(self) -> Transaction:
        return Transaction(self.version, [i.copy() for i in self.vin], [o.copy() for o in self.vout], self.locktime)

    def digest_legacy(self, i: int, hash_type: int, script_code: bytearray) -> bytearray:
        # The legacy signing algorithm is used to create signatures that will unlock non-segwit locking scripts.
        # See: https://learnmeabitcoin.com/technical/keys/signature/
        ht = HashType(hash_type)
        tx = self.copy()
        for e in tx.vin:
            e.script_sig = bytearray()
        # Put the script_pubkey as a placeholder in the script_sig. If the output is a p2sh output, then we need to use
        # the redeem script.
        tx.vin[i].script_sig = script_code
        if ht.i == sighash_anyone_can_pay:
            tx.vin = [tx.vin[i]]
        if ht.o == sighash_none:
            tx.vout = []
        if ht.o == sighash_single:
            tx.vout = [tx.vout[i]]
        data = tx.serialize_legacy()
        # Append signature hash type to transaction data. The most common is SIGHASH_ALL (0x01), which indicates that
        # the signature covers all of the inputs and outputs in the transaction. This means that nobody else can add
        # any additional inputs or outputs to it later on.
        # The sighash when appended to the transaction data is 4 bytes and in little-endian byte order.
        data.extend(bytearray([hash_type, 0x00, 0x00, 0x00]))
        return hash256(data)

    def digest_segwit_v0(self, i: int, hash_type: int, script_code: bytearray) -> bytearray:
        # A new transaction digest algorithm for signature verification in version 0 witness program, in order to
        # minimize redundant data hashing in verification, and to cover the input value by the signature.
        # See: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        ht = HashType(hash_type)
        data = bytearray()
        # Append version of the transaction.
        data.extend(self.version.to_bytes(4, 'little'))
        # Append hash prevouts.
        hash = bytearray(32)
        if ht.i != sighash_anyone_can_pay:
            snap = bytearray()
            for e in self.vin:
                snap.extend(e.out_point.txid)
                snap.extend(e.out_point.vout.to_bytes(4, 'little'))
            hash = hash256(snap)
        data.extend(hash)
        # Append hash sequence.
        hash = bytearray(32)
        if ht.i != sighash_anyone_can_pay and ht.o != sighash_single and ht.o != sighash_none:
            snap = bytearray()
            for e in self.vin:
                snap.extend(e.sequence.to_bytes(4, 'little'))
            hash = hash256(snap)
        data.extend(hash)
        # Append outpoint.
        data.extend(self.vin[i].out_point.txid)
        data.extend(self.vin[i].out_point.vout.to_bytes(4, 'little'))
        # Append script code of the input.
        data.extend(pabtc.compact_size.encode(len(script_code)))
        data.extend(script_code)
        # Append value of the output spent by this input.
        data.extend(self.vin[i].out_point.load().value.to_bytes(8, 'little'))
        # Append sequence of the input.
        data.extend(self.vin[i].sequence.to_bytes(4, 'little'))
        # Append hash outputs.
        hash = bytearray(32)
        if ht.o == sighash_all:
            snap = bytearray()
            for e in self.vout:
                snap.extend(e.value.to_bytes(8, 'little'))
                snap.extend(pabtc.compact_size.encode(len(e.script_pubkey)))
                snap.extend(e.script_pubkey)
            hash = hash256(snap)
        if ht.o == sighash_single and i < len(self.vout):
            snap = bytearray()
            snap.extend(self.vout[i].value.to_bytes(8, 'little'))
            snap.extend(pabtc.compact_size.encode(len(self.vout[i].script_pubkey)))
            snap.extend(self.vout[i].script_pubkey)
            hash = hash256(snap)
        data.extend(hash)
        # Append locktime of the transaction.
        data.extend(self.locktime.to_bytes(4, 'little'))
        # Append sighash type of the signature.
        data.extend(bytearray([hash_type, 0x00, 0x00, 0x00]))
        return hash256(data)

    def digest_segwit_v1(self, i: int, hash_type: int, script_code: bytearray) -> bytearray:
        # See: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
        ht = HashType(hash_type)
        data = bytearray()
        # This prefix is called the sighash epoch, and allows reusing the hashTapSighash tagged hash in future
        # signature algorithms that make invasive changes to how hashing is performed (as opposed to the ext_flag
        # mechanism that is used for incremental extensions). An alternative is having them use a different tag, but
        # supporting a growing number of tags may become undesirable.
        data.append(0x00)
        data.append(hash_type)
        data.extend(self.version.to_bytes(4, 'little'))
        data.extend(self.locktime.to_bytes(4, 'little'))
        if ht.i != sighash_anyone_can_pay:
            # Append the SHA256 of the serialization of all input outpoints.
            snap = bytearray()
            for e in self.vin:
                snap.extend(e.out_point.txid)
                snap.extend(e.out_point.vout.to_bytes(4, 'little'))
            data.extend(bytearray(hashlib.sha256(snap).digest()))
            # Append the SHA256 of the serialization of all input amounts.
            snap = bytearray()
            for e in self.vin:
                utxo = e.out_point.load()
                snap.extend(utxo.value.to_bytes(8, 'little'))
            data.extend(bytearray(hashlib.sha256(snap).digest()))
            # Append the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut.
            snap = bytearray()
            for e in self.vin:
                utxo = e.out_point.load()
                snap.extend(pabtc.compact_size.encode(len(utxo.script_pubkey)))
                snap.extend(utxo.script_pubkey)
            data.extend(bytearray(hashlib.sha256(snap).digest()))
            # Append the SHA256 of the serialization of all input nSequence.
            snap = bytearray()
            for e in self.vin:
                snap.extend(e.sequence.to_bytes(4, 'little'))
            data.extend(bytearray(hashlib.sha256(snap).digest()))
        if ht.o == sighash_all:
            snap = bytearray()
            for e in self.vout:
                snap.extend(e.value.to_bytes(8, 'little'))
                snap.extend(pabtc.compact_size.encode(len(e.script_pubkey)))
                snap.extend(e.script_pubkey)
            data.extend(bytearray(hashlib.sha256(snap).digest()))
        spend_type = 0x00
        if script_code:
            spend_type |= 0x2
        data.append(spend_type)
        if ht.i == sighash_anyone_can_pay:
            data.extend(self.vin[i].out_point.txid)
            data.extend(self.vin[i].out_point.vout.to_bytes(4, 'little'))
            utxo = self.vin[i].out_point.load()
            data.extend(utxo.value.to_bytes(8, 'little'))
            data.extend(pabtc.compact_size.encode(len(utxo.script_pubkey)))
            data.extend(utxo.script_pubkey)
            data.extend(self.vin[i].sequence.to_bytes(4, 'little'))
        if ht.i != sighash_anyone_can_pay:
            data.extend(i.to_bytes(4, 'little'))
        if ht.o == sighash_single:
            snap = bytearray()
            # Using SIGHASH_SINGLE without a "corresponding output" (an output with the same index as the input being
            # verified) cause validation failure.
            snap.extend(self.vout[i].value.to_bytes(8, 'little'))
            snap.extend(pabtc.compact_size.encode(len(self.vout[i].script_pubkey)))
            snap.extend(self.vout[i].script_pubkey)
            data.extend(bytearray(hashlib.sha256(snap).digest()))
        # See: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
        if script_code:
            snap = bytearray()
            snap.append(0xc0)
            snap.extend(pabtc.compact_size.encode(len(script_code)))
            snap.extend(script_code)
            data.extend(hashtag('TapLeaf', snap))
            data.append(0x00)
            data.extend(0xffffffff.to_bytes(4, 'little'))
        size = 1 + 174
        if ht.i == sighash_anyone_can_pay:
            size -= 49
        if ht.o == sighash_none:
            size -= 32
        if script_code:
            size += 37
        assert len(data) == size
        return hashtag('TapSighash', data)

    def json(self) -> typing.Dict:
        return {
            'version': self.version,
            'vin': [e.json() for e in self.vin],
            'vout': [e.json() for e in self.vout],
            'locktime': self.locktime,
        }

    def serialize_legacy(self) -> bytearray:
        data = bytearray()
        data.extend(self.version.to_bytes(4, 'little'))
        data.extend(pabtc.compact_size.encode(len(self.vin)))
        for i in self.vin:
            data.extend(i.out_point.txid)
            data.extend(i.out_point.vout.to_bytes(4, 'little'))
            data.extend(pabtc.compact_size.encode(len(i.script_sig)))
            data.extend(i.script_sig)
            data.extend(i.sequence.to_bytes(4, 'little'))
        data.extend(pabtc.compact_size.encode(len(self.vout)))
        for o in self.vout:
            data.extend(o.value.to_bytes(8, 'little'))
            data.extend(pabtc.compact_size.encode(len(o.script_pubkey)))
            data.extend(o.script_pubkey)
        data.extend(self.locktime.to_bytes(4, 'little'))
        return data

    def serialize_segwit(self) -> bytearray:
        data = bytearray()
        data.extend(self.version.to_bytes(4, 'little'))
        data.append(0x00)
        data.append(0x01)
        data.extend(pabtc.compact_size.encode(len(self.vin)))
        for i in self.vin:
            data.extend(i.out_point.txid)
            data.extend(i.out_point.vout.to_bytes(4, 'little'))
            data.extend(pabtc.compact_size.encode(len(i.script_sig)))
            data.extend(i.script_sig)
            data.extend(i.sequence.to_bytes(4, 'little'))
        data.extend(pabtc.compact_size.encode(len(self.vout)))
        for o in self.vout:
            data.extend(o.value.to_bytes(8, 'little'))
            data.extend(pabtc.compact_size.encode(len(o.script_pubkey)))
            data.extend(o.script_pubkey)
        for i in self.vin:
            data.extend(pabtc.compact_size.encode(len(i.witness)))
            for e in i.witness:
                data.extend(pabtc.compact_size.encode(len(e)))
                data.extend(e)
        data.extend(self.locktime.to_bytes(4, 'little'))
        return data

    def serialize(self) -> bytearray:
        # If any inputs have nonempty witnesses, the entire transaction is serialized in the BIP141 Segwit format which
        # includes a list of witnesses.
        # See: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        if any([e.witness for e in self.vin]):
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    @classmethod
    def serialize_decode_legacy(cls, data: bytearray) -> Transaction:
        reader = io.BytesIO(data)
        tx = Transaction(0, [], [], 0)
        tx.version = int.from_bytes(reader.read(4), 'little')
        for _ in range(pabtc.compact_size.decode_reader(reader)):
            txid = bytearray(reader.read(32))
            vout = int.from_bytes(reader.read(4), 'little')
            script_sig = bytearray(reader.read(pabtc.compact_size.decode_reader(reader)))
            sequence = int.from_bytes(reader.read(4), 'little')
            tx.vin.append(TxIn(OutPoint(txid, vout), script_sig, sequence, []))
        for _ in range(pabtc.compact_size.decode_reader(reader)):
            value = int.from_bytes(reader.read(8), 'little')
            script_pubkey = bytearray(reader.read(pabtc.compact_size.decode_reader(reader)))
            tx.vout.append(TxOut(value, script_pubkey))
        tx.locktime = int.from_bytes(reader.read(4), 'little')
        return tx

    @classmethod
    def serialize_decode_segwit(cls, data: bytearray) -> Transaction:
        reader = io.BytesIO(data)
        tx = Transaction(0, [], [], 0)
        tx.version = int.from_bytes(reader.read(4), 'little')
        assert reader.read(1)[0] == 0x00
        assert reader.read(1)[0] == 0x01
        for _ in range(pabtc.compact_size.decode_reader(reader)):
            txid = bytearray(reader.read(32))
            vout = int.from_bytes(reader.read(4), 'little')
            script_sig = bytearray(reader.read(pabtc.compact_size.decode_reader(reader)))
            sequence = int.from_bytes(reader.read(4), 'little')
            tx.vin.append(TxIn(OutPoint(txid, vout), script_sig, sequence, []))
        for _ in range(pabtc.compact_size.decode_reader(reader)):
            value = int.from_bytes(reader.read(8), 'little')
            script_pubkey = bytearray(reader.read(pabtc.compact_size.decode_reader(reader)))
            tx.vout.append(TxOut(value, script_pubkey))
        for i in range(len(tx.vin)):
            wits = []
            for _ in range(pabtc.compact_size.decode_reader(reader)):
                wits.append(bytearray(reader.read(pabtc.compact_size.decode_reader(reader))))
            tx.vin[i].witness = wits
        tx.locktime = int.from_bytes(reader.read(4), 'little')
        return tx

    @classmethod
    def serialize_decode(cls, data: bytearray) -> Transaction:
        if data[4] == 0x00:
            return Transaction.serialize_decode_segwit(data)
        else:
            return Transaction.serialize_decode_legacy(data)

    def txid(self) -> bytearray:
        return hash256(self.serialize_legacy())

    def vbytes(self) -> int:
        return math.ceil(self.weight() / 4.0)

    def weight(self) -> int:
        size_legacy = len(self.serialize_legacy())
        size_segwit = len(self.serialize_segwit()) - size_legacy
        return size_legacy * 4 + size_segwit


class Message:
    def __init__(self, data: str) -> None:
        self.data = data

    def hash(self) -> bytearray:
        b = bytearray()
        # Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
        b.extend(pabtc.core.pabtc.compact_size.encode(24))
        b.extend(bytearray('Bitcoin Signed Message:\n'.encode()))
        b.extend(pabtc.core.pabtc.compact_size.encode(len(self.data)))
        b.extend(bytearray(self.data.encode()))
        return pabtc.core.hash256(b)

    def sign(self, prikey: PriKey) -> str:
        r, s, v = prikey.sign_ecdsa(self.hash())
        # Header Byte has the following ranges:
        #   27-30: P2PKH uncompressed
        #   31-34: P2PKH compressed
        #   35-38: Segwit P2SH
        #   39-42: Segwit Bech32
        # See: https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki.
        sig = bytearray([31 + v]) + bytearray(r.n.to_bytes(32)) + bytearray(s.n.to_bytes(32))
        return base64.b64encode(sig).decode()

    def pubkey(self, sig: str) -> PubKey:
        m = pabtc.secp256k1.Fr(int.from_bytes(self.hash()))
        b = base64.b64decode(sig)
        assert b[0] >= 27
        v = (b[0] - 27) & 3
        r = pabtc.secp256k1.Fr(int.from_bytes(b[0x01:0x21]))
        s = pabtc.secp256k1.Fr(int.from_bytes(b[0x21:0x41]))
        return PubKey.pt_decode(pabtc.ecdsa.pubkey(m, r, s, v))
