import pabtc


def test_generate_to_address():
    pabtc.config.current = pabtc.config.develop
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    addr = pabtc.core.address_p2wpkh(pubkey)
    hash = pabtc.rpc.generate_to_address(4, addr)
    assert len(hash) == 4


def test_get_best_block_hash():
    pabtc.config.current = pabtc.config.develop
    hash = pabtc.rpc.get_best_block_hash()
    assert len(hash) == 64


def test_get_block_count():
    pabtc.config.current = pabtc.config.develop
    assert pabtc.rpc.get_block_count() != 0


def test_sign_message_with_privkey():
    pabtc.config.current = pabtc.config.develop
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    sigs = pabtc.rpc.sign_message_with_privkey(prikey.wif(), 'my message')
    assert pabtc.core.Message('my message').pubkey(sigs) == pubkey


def test_validate_address():
    pabtc.config.current = pabtc.config.develop
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    addr = pabtc.core.address_p2pkh(pubkey)
    rets = pabtc.rpc.validate_address(addr)
    assert rets['isvalid'] is True
    assert rets['address'] == addr
    assert rets['scriptPubKey'] == pabtc.core.script_pubkey_p2pkh(addr).hex()
    addr = pabtc.core.address_p2sh_p2wpkh(pubkey)
    rets = pabtc.rpc.validate_address(addr)
    assert rets['isvalid'] is True
    assert rets['address'] == addr
    assert rets['scriptPubKey'] == pabtc.core.script_pubkey_p2sh(addr).hex()
    addr = pabtc.core.address_p2wpkh(pubkey)
    rets = pabtc.rpc.validate_address(addr)
    assert rets['isvalid'] is True
    assert rets['address'] == addr
    assert rets['scriptPubKey'] == pabtc.core.script_pubkey_p2wpkh(addr).hex()
    addr = pabtc.core.address_p2tr(pubkey, bytearray())
    rets = pabtc.rpc.validate_address(addr)
    assert rets['isvalid'] is True
    assert rets['address'] == addr
    assert rets['scriptPubKey'] == pabtc.core.script_pubkey_p2tr(addr).hex()


def test_verify_message():
    pabtc.config.current = pabtc.config.develop
    prikey = pabtc.core.PriKey(1)
    pubkey = prikey.pubkey()
    addr = pabtc.core.address_p2pkh(pubkey)
    sigs = pabtc.core.Message('my message').sign(prikey)
    assert pabtc.rpc.verify_message(addr, sigs, 'my message') is True
