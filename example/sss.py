import argparse
import pabtc
import secrets

# Shamir's secret sharing. See https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing.
# Usage:
#   1. Produce shares:
#       python sss.py -m 2 -n 3 prikey
#   2. Recover secret:
#       python sss.py -m 2 -n 3 share0 share1 share2

parser = argparse.ArgumentParser()
parser.add_argument('-m', type=int, help='m-of-n, number of threshold')
parser.add_argument('-n', type=int, help='m-of-n, number of shares')
parser.add_argument('args', nargs='+', help='prikey or shares')
args = parser.parse_args()

Fq = pabtc.secp256k1.Fq


def polysum(coeffs: list[Fq], x: Fq) -> Fq:
    # Evaluate polynomial sum(coeffs[i] * x^i) mod P.
    rets = Fq.nil()
    xpow = Fq.one()
    for c in coeffs:
        rets = rets + c * xpow
        xpow = xpow * x
    return rets


def produce(secret: Fq, m: int, n: int) -> list[list[Fq]]:
    # Degree-(m-1) polynomial: f(x) = secret + a1*x + ... + a_{m-1}*x^{m-1}
    coeffs = [secret] + [Fq(secrets.randbelow(Fq.p - 1) + 1) for _ in range(m - 1)]
    shares = []
    for i in range(1, n + 1):
        y = polysum(coeffs, Fq(i))
        shares.append([Fq(i), y])
    return shares


def recover(shares: list[list[Fq]]) -> Fq:
    # Lagrange interpolation at x = 0 over Fq.
    secret = Fq.nil()
    k = len(shares)
    for i in range(k):
        xi, yi = shares[i]
        num = Fq.one()
        den = Fq.one()
        for j in range(k):
            if i == j:
                continue
            xj = shares[j][0]
            num = num * -xj
            den = den * (xi - xj)
        secret = secret + yi * num / den
    return secret


if len(args.args) == 1:
    points = args.args[0].split(':')
    assert points[0] == '0x0'
    prikey = int(points[1], 16)
    shares = produce(Fq(prikey), args.m, args.n)
    for e in shares:
        print(f'0x{e[0].n:x}:0x{e[1].n:064x}')

if len(args.args) >= 2:
    shares = [[Fq(int(e, 16)) for e in s.split(':')] for s in args.args]
    prikey = recover(shares)
    print(f'0x0:0x{prikey.n:064x}')
