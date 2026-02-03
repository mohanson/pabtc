import argparse
import pabtc

# Calculate the address from a private key.

parser = argparse.ArgumentParser()
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
parser.add_argument('--prikey', type=str, required=True, help='private key')
args = parser.parse_args()

if args.net == 'develop':
    pabtc.config.current = pabtc.config.develop
if args.net == 'mainnet':
    pabtc.config.current = pabtc.config.mainnet
if args.net == 'testnet':
    pabtc.config.current = pabtc.config.testnet

prikey = pabtc.core.PriKey(int(args.prikey, 0))
pubkey = prikey.pubkey()
pubkey_p2tr = bytearray(pabtc.taproot.pubkey_tweak(pubkey.pt(), bytearray()).x.n.to_bytes(32))

print('p2pkh      ', pabtc.core.Address.p2pkh(pubkey.hash()))
print('p2sh-p2wpkh', pabtc.core.Address.p2sh_p2wpkh(pubkey.hash()))
print('p2wpkh     ', pabtc.core.Address.p2wpkh(pubkey.hash()))
print('p2tr       ', pabtc.core.Address.p2tr(pubkey_p2tr))
