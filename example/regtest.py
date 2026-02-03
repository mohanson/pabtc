import pabtc

pub1 = pabtc.core.PriKey(1).pubkey()
pub2 = pabtc.core.PriKey(2).pubkey()

pabtc.rpc.call('createwallet', ['main', True, True, None, None, None, True])
for d in [
    f'pkh({pub1.sec().hex()})',
    f'pkh({pub2.sec().hex()})',
    f'sh(multi(2,{pub1.sec().hex()},{pub2.sec().hex()}))',
    f'sh(multi(2,{pub2.sec().hex()},{pub1.sec().hex()}))',
    f'sh(wpkh({pub1.sec().hex()}))',
    f'sh(wpkh({pub2.sec().hex()}))',
    f'wpkh({pub1.sec().hex()})',
    f'wpkh({pub2.sec().hex()})',
    f'tr({pub1.sec().hex()})',
    f'tr({pub2.sec().hex()})',
]:
    d = pabtc.rpc.get_descriptor_info(d)['descriptor']
    pabtc.rpc.import_descriptors([{
        'desc': d,
        'timestamp': 0,
    }])
pabtc.rpc.generate_to_address(10, pabtc.core.Address.p2pkh(pub1.hash()))
pabtc.rpc.generate_to_address(10, pabtc.core.Address.p2sh_p2ms(2, [pub1, pub2]))
pabtc.rpc.generate_to_address(10, pabtc.core.Address.p2sh_p2wpkh(pub1.hash()))
pabtc.rpc.generate_to_address(10, pabtc.core.Address.p2wpkh(pub1.hash()))
p2tr_pubkey = bytearray(pabtc.taproot.pubkey_tweak(pub1.pt(), bytearray()).x.n.to_bytes(32))
pabtc.rpc.generate_to_address(10, pabtc.core.Address.p2tr(p2tr_pubkey))
pabtc.rpc.generate_to_address(99, pabtc.core.Address.p2pkh(pub1.hash()))
