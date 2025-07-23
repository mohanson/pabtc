import pabtc

# Brute-forcing the private key of Satoshi Nakamoto's address.
pabtc.config.current = pabtc.config.mainnet

for _ in range(1 << 32):
    prikey = pabtc.core.PriKey.random()
    pubkey = prikey.pubkey()
    addr = pabtc.core.address_p2pkh(pubkey)
    print(prikey, addr)
    # This is the Genesis address, it is owned by Satoshi Nakamoto and contains the unspendable 50 bitcoin mined from
    # the genesis block.
    if addr == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa':
        print('Oh my god, you did it!')
        break
