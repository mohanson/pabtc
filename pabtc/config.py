import pabtc.objectdict

develop = pabtc.objectdict.ObjectDict({
    'rpc': {
        'url': 'http://127.0.0.1:18443',
        'qps': 32,
        'username': 'user',
        'password': 'pass',
    },
    'prefix': {
        'base58': {
            'p2pkh': 0x6f,
            'p2sh': 0xc4,
            'wif': 0xef,
        },
        'bech32': 'bcrt',
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
        'base58': {
            'p2pkh': 0x00,
            'p2sh': 0x05,
            'wif': 0x80,
        },
        'bech32': 'bc',
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
        'base58': {
            'p2pkh': 0x6f,
            'p2sh': 0xc4,
            'wif': 0xef,
        },
        'bech32': 'tb',
    },
})

current = develop
