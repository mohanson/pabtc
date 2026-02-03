import io
import typing


# Integer can be encoded depending on the represented value to save space. Variable length integers always precede an
# array/vector of a type of data that may vary in length. Longer numbers are encoded in little endian.
# See: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

def encode(n: int) -> bytearray:
    assert n >= 0
    assert n <= 0xffffffffffffffff
    if n <= 0xfc:
        return bytearray([n])
    if n <= 0xffff:
        return bytearray([0xfd]) + bytearray(n.to_bytes(2, 'little'))
    if n <= 0xffffffff:
        return bytearray([0xfe]) + bytearray(n.to_bytes(4, 'little'))
    if n <= 0xffffffffffffffff:
        return bytearray([0xff]) + bytearray(n.to_bytes(8, 'little'))
    raise Exception('unreachable')


def decode(data: bytearray) -> int:
    return decode_reader(io.BytesIO(data))


def decode_reader(reader: typing.BinaryIO) -> int:
    head = reader.read(1)[0]
    if head <= 0xfc:
        return head
    if head == 0xfd:
        return int.from_bytes(reader.read(2), 'little')
    if head == 0xfe:
        return int.from_bytes(reader.read(4), 'little')
    if head == 0xff:
        return int.from_bytes(reader.read(8), 'little')
    raise Exception('unreachable')
