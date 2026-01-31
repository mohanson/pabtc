import pabtc
import random
import string


def test_address_p2pkh():
    pabtc.config.current = pabtc.config.mainnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2pkh(pubkey_hash)
    assert addr == '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
    pubkey_hash = bytearray.fromhex('f587ce33cf12ff1dd4cf3b3f861b22785315335f')
    addr = pabtc.core.Address.p2pkh(pubkey_hash)
    assert addr == '1PPFEvrSYyLBFBTqnDVujY15fLMg1i8H43'
    pabtc.config.current = pabtc.config.testnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2pkh(pubkey_hash)
    assert addr == 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r'


def test_address_p2sh():
    # https://en.bitcoin.it/wiki/Pay_to_script_hash
    # https://mempool.space/tx/40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8
    pabtc.config.current = pabtc.config.mainnet
    pubkey = bytearray()
    pubkey.append(0x04)
    pubkey.extend(bytearray.fromhex('2f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a5878'))
    pubkey.extend(bytearray.fromhex('8505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf'))
    redeem = bytearray()
    redeem.append(pabtc.opcode.op_1)
    redeem.extend(pabtc.opcode.op_pushdata(pubkey))
    redeem.append(pabtc.opcode.op_1)
    redeem.append(pabtc.opcode.op_checkmultisig)
    redeem_hash = pabtc.core.hash160(redeem)
    addr = pabtc.core.Address.p2sh(redeem_hash)
    assert addr == '3P14159f73E4gFr7JterCCQh9QjiTjiZrG'


def test_address_p2sh_p2ms():
    pabtc.config.current = pabtc.config.mainnet
    pubkey = [pabtc.core.PubKey.sec_decode(bytearray.fromhex(e)) for e in [
        '022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e',
        '03a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c0',
    ]]
    addr = pabtc.core.Address.p2sh_p2ms(1, pubkey)
    assert addr == '3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V'
    pabtc.config.current = pabtc.config.develop
    pubkey = [pabtc.core.PubKey.sec_decode(bytearray.fromhex(e)) for e in [
        '03150176a55b6d77eec5740c1f87f434cf416d5bbde1704bd816288a4466afb7bb',
        '02c3b2d3baf90e559346895b43253407fbb345c146910837b61f301f4c9a7edfe5',
        '02c6e3e94f7ff77457da9e76cf0779ca7c1e8575db064a2ea55400e6a9d8190225',
    ]]
    addr = pabtc.core.Address.p2sh_p2ms(2, pubkey)
    assert addr == '2MyxShnGQ5NifGb8CHYrtmzosRySxZ9pZo5'


def test_address_p2sh_p2wpkh():
    pabtc.config.current = pabtc.config.mainnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2sh_p2wpkh(pubkey_hash)
    assert addr == '3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN'
    pabtc.config.current = pabtc.config.testnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2sh_p2wpkh(pubkey_hash)
    assert addr == '2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN'


def test_address_p2sh_p2wsh():
    pabtc.config.current = pabtc.config.mainnet
    redeem_hash = bytearray.fromhex('973cfd44e60501c38320ab1105fb3ee3916d2952702e3c8cb4cbb7056aa6b47f')
    addr = pabtc.core.Address.p2sh_p2wsh(redeem_hash)
    assert addr == '356yCBhiW9tqg5iiPDhEZ8f8t3JfqkEihA'


def test_address_p2wpkh():
    pabtc.config.current = pabtc.config.mainnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2wpkh(pubkey_hash)
    assert addr == 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    pubkey_hash = bytearray.fromhex('841b80d2cc75f5345c482af96294d04fdd66b2b7')
    addr = pabtc.core.Address.p2wpkh(pubkey_hash)
    assert addr == 'bc1qssdcp5kvwh6nghzg9tuk99xsflwkdv4hgvq58q'
    pabtc.config.current = pabtc.config.testnet
    pubkey_hash = pabtc.core.PriKey(1).pubkey().hash()
    addr = pabtc.core.Address.p2wpkh(pubkey_hash)
    assert addr == 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'


def test_address_p2wsh():
    pabtc.config.current = pabtc.config.mainnet
    redeem = pabtc.core.ScriptPubKey.p2ms(2, [pabtc.core.PubKey.sec_decode(bytearray.fromhex(e)) for e in [
        '03848e308569b644372a5eb26665f1a8c34ca393c130b376db2fae75c43500013c',
        '03cec1ee615c17e06d4f4b0a08617dffb8e568936bdff18fb057832a58ad4d1b75',
        '03eed7ae80c34d70f5ba93f93965f69f3c691da0f4607f242f4fd6c7a48789233e',
    ]])
    redeem_hash = pabtc.core.hashwsh(redeem)
    assert redeem_hash.hex() == '65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3'
    addr = pabtc.core.Address.p2wsh(redeem_hash)
    assert addr == 'bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65'


def test_address_p2wsh_p2ms():
    pabtc.config.current = pabtc.config.mainnet
    pubkey = [pabtc.core.PubKey.sec_decode(bytearray.fromhex(e)) for e in [
        '03848e308569b644372a5eb26665f1a8c34ca393c130b376db2fae75c43500013c',
        '03cec1ee615c17e06d4f4b0a08617dffb8e568936bdff18fb057832a58ad4d1b75',
        '03eed7ae80c34d70f5ba93f93965f69f3c691da0f4607f242f4fd6c7a48789233e',
    ]]
    addr = pabtc.core.Address.p2wsh_p2ms(2, pubkey)
    assert addr == 'bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65'


def test_address_p2tr():
    pabtc.config.current = pabtc.config.mainnet
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    addr = pabtc.core.address_p2tr(pubkey, bytearray())
    assert addr == 'bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9'
    pabtc.config.current = pabtc.config.testnet
    addr = pabtc.core.address_p2tr(pubkey, bytearray())
    assert addr == 'tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2'


def test_compact_size():
    for n, b in [
        [0xbb, bytearray([0xbb])],
        [0xff, bytearray([0xfd, 0xff, 0x00])],
        [0x3419, bytearray([0xfd, 0x19, 0x34])],
        [0xdc4591, bytearray([0xfe, 0x91, 0x45, 0xdc, 00])],
        [0x80081e5, bytearray([0xfe, 0xe5, 0x81, 0x00, 0x08])],
        [0xb4da564e2857, bytearray([0xff, 0x57, 0x28, 0x4e, 0x56, 0xda, 0xb4, 0x00, 0x00])],
        [0x4bf583a17d59c158, bytearray([0xff, 0x58, 0xc1, 0x59, 0x7d, 0xa1, 0x83, 0xf5, 0x4b])],
    ]:
        assert pabtc.core.compact_size_encode(n) == b
        assert pabtc.core.compact_size_decode(b) == n


def test_difficulty_target():
    assert pabtc.core.difficulty_target(
        0x1b0404cb) == 0x00000000000404CB000000000000000000000000000000000000000000000000
    assert pabtc.core.difficulty_target(
        0x1d00ffff) == 0x00000000FFFF0000000000000000000000000000000000000000000000000000


def test_hash160():
    hash = pabtc.core.hash160(bytearray([0, 1, 2, 3]))
    assert hash.hex() == '3c3fa3d4adcaf8f52d5b1843975e122548269937'


def test_message():
    for _ in range(4):
        prikey = pabtc.core.PriKey.random()
        pubkey = prikey.pubkey()
        msg = pabtc.core.Message(''.join(random.choice(string.ascii_letters) for _ in range(random.randint(0, 1024))))
        sig = msg.sign(prikey)
        assert msg.pubkey(sig) == pubkey


def test_prikey():
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


def test_prikey_wif():
    pabtc.config.current = pabtc.config.mainnet
    prikey = pabtc.core.PriKey(1)
    assert prikey.wif() == 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
    assert prikey == pabtc.core.PriKey.wif_decode(prikey.wif())
    pabtc.config.current = pabtc.config.testnet
    assert prikey.wif() == 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA'
    assert prikey == pabtc.core.PriKey.wif_decode(prikey.wif())


def test_pubkey_sec():
    pubkey = pabtc.core.PubKey(
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )
    assert pubkey.sec().hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'


def test_pubkey_sec_read():
    pubkey = pabtc.core.PubKey.sec_decode(bytearray.fromhex(''.join([
        '04',
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    ])))
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    pubkey = pabtc.core.PubKey.sec_decode(bytearray.fromhex(''.join([
        '02',
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    ])))
    assert pubkey.x == 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    assert pubkey.y == 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


def test_transaction():
    # Data copied from mastering bitcoin, chapter 6, example 1, alice's serialized transaction.
    # See: https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch06_transactions.adoc
    data = bytearray([
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xeb, 0x3a, 0xe3, 0x8f, 0x27, 0x19, 0x1a, 0xa5, 0xf3,
        0x85, 0x0d, 0xc9, 0xca, 0xd0, 0x04, 0x92, 0xb8, 0x8b, 0x72, 0x40, 0x4f, 0x9d, 0xa1, 0x35, 0x69,
        0x86, 0x79, 0x26, 0x80, 0x41, 0xc5, 0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x02, 0x20, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x51, 0x20, 0x3b, 0x41, 0xda, 0xba,
        0x4c, 0x9a, 0xce, 0x57, 0x83, 0x69, 0x74, 0x0f, 0x15, 0xe5, 0xec, 0x88, 0x0c, 0x28, 0x27, 0x9e,
        0xe7, 0xf5, 0x1b, 0x07, 0xdc, 0xa6, 0x9c, 0x70, 0x61, 0xe0, 0x70, 0x68, 0xf8, 0x24, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x77, 0x52, 0xc1, 0x65, 0xea, 0x7b, 0xe7, 0x72, 0xb2,
        0xc0, 0xac, 0xb7, 0xf4, 0xd6, 0x04, 0x7a, 0xe6, 0xf4, 0x76, 0x8e, 0x01, 0x41, 0xcf, 0x5e, 0xfe,
        0x2d, 0x8e, 0xf1, 0x3e, 0xd0, 0xaf, 0x21, 0xd4, 0xf4, 0xcb, 0x82, 0x42, 0x2d, 0x62, 0x52, 0xd7,
        0x03, 0x24, 0xf6, 0xf4, 0x57, 0x6b, 0x72, 0x7b, 0x7d, 0x91, 0x8e, 0x52, 0x1c, 0x00, 0xb5, 0x1b,
        0xe7, 0x39, 0xdf, 0x2f, 0x89, 0x9c, 0x49, 0xdc, 0x26, 0x7c, 0x0a, 0xd2, 0x80, 0xac, 0xa6, 0xda,
        0xb0, 0xd2, 0xfa, 0x2b, 0x42, 0xa4, 0x51, 0x82, 0xfc, 0x83, 0xe8, 0x17, 0x13, 0x01, 0x00, 0x00,
        0x00, 0x00,
    ])
    tx = pabtc.core.Transaction.serialize_decode(data)
    assert tx.serialize() == data
    assert tx.version == 1
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.locktime == 0
    assert tx.weight() == 569
    assert tx.txid() == bytearray.fromhex('7761f9d1ecbcf9c129802aaadfdfec38419aa441519d94bc5b21968630006246')


def test_witness():
    for _ in range(256):
        wits = [bytearray(random.randbytes(random.randint(0, 256))) for _ in range(random.randint(0, 256))]
        assert pabtc.core.witness_decode(pabtc.core.witness_encode(wits)) == wits
