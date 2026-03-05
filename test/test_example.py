import subprocess


def call(c: str):
    return subprocess.run(c, check=True, shell=True)


def test_addr():
    call('python example/addr.py --net mainnet --prikey 1')


def test_message():
    call('python example/message.py --prikey 1 --msg pybtc')
    call('python example/message.py --prikey 1 --msg pybtc --sig ICvzXjwjJVMilSGyMqwlqMTuGF6UMwddFJzVmm0Di5qNnqkBRKP8Pldm3YbOskg3ewV1tszVLy8gVX1u+qFrx6o=')


def test_sss():
    call('python example/sss.py -m 2 -n 3 0x0:0x0000000000000000000000000000000000000000000000000000000000000001')
    call('python example/sss.py -m 2 -n 3 0x2:0x5dee2bfbf85ebe932a0b305c621d9e6bbbb578a4c6d9eaa62a6a9cb9b923df92 0x3:0x0ce541f9f48e1ddcbf10c88a932c6da1999034f72a46dff93f9feb1715b5d143')


def test_taproot():
    call('python example/taproot.py')


def test_transfer():
    call('python example/transfer.py --net develop --prikey 1 --script-type p2pkh --to mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H --value 0.1')
