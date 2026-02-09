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
    'wallet': {
        # Satoshi per vbyte. Zero means to use the node's fee estimation.
        'fee_rate': 0,
        # Make sure fee_rate <= fee_rate_max.
        'fee_rate_max': 9,
        # Make sure fee_rate >= fee_rate_min.
        'fee_rate_min': 0,
    }
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
    'wallet': {
        'fee_rate': 0,
        'fee_rate_max': 9,
        'fee_rate_min': 0,
    }
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
    'wallet': {
        'fee_rate': 0,
        'fee_rate_max': 9,
        'fee_rate_min': 0,
    }
})

current = develop
