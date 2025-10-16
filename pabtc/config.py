import pabtc.objectdict

develop = pabtc.objectdict.ObjectDict({
    'rpc': {
        'url': 'http://127.0.0.1:18443',
        'qps': 32,
        'username': 'user',
        'password': 'pass',
    },
    'prefix': {
        'p2pkh': 0x6f,
        'p2sh': 0xc4,
        'bech32': 'bcrt',
        'wif': 0xef,
    },
})

mainnet = pabtc.objectdict.ObjectDict({
    'rpc': {
        'url': 'https://bitcoin.drpc.org/',
        'qps': 2,
        'username': '',
        'password': '',
    },
    'prefix': {
        'p2pkh': 0x00,
        'p2sh': 0x05,
        'bech32': 'bc',
        'wif': 0x80,
    },
})

testnet = pabtc.objectdict.ObjectDict({
    'rpc': {
        'url': 'https://bitcoin-testnet.drpc.org/',
        'qps': 2,
        'username': '',
        'password': '',
    },
    'prefix': {
        'p2pkh': 0x6f,
        'p2sh': 0xc4,
        'bech32': 'tb',
        'wif': 0xef,
    },
})

current = develop
