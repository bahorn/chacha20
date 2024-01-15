"""
A pure-python ChaCha20 implementation.
"""
import struct


def m32(n):
    return n & 0xffffffff


def madd(a, b):
    return m32(a + b)


def mls(a, b):
    return m32(a << b)


def mrs(a, b):
    return m32(a >> b)


def rotl(a, b):
    return (mls(a, b) | mrs(a, 32 - b))


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def bytes_to_int_list(b, size=4):
    return list(map(lambda x: struct.unpack('<I', x)[0], chunks(b, size)))


def ints_to_bytes(seq):
    return b''.join(map(lambda x: struct.pack('<I', x), seq))


class ChaCha20:
    """
    A ChaCha20 implementation, based off the C implementation found on
    wikipedia, with review of the salsa20 and chacha20 papers.

    https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
    """
    STATESIZE = 16

    def __init__(self, key, nonce, counter=0):
        if len(key) != 32:
            raise Exception("Key is not 16 bytes!")
        if len(nonce) != 8:
            raise Exception("Nonce is not 8 bytes!")
        self._key = key
        self._nonce = nonce
        self._counter = counter
        self._left = b''

    def _init(self, counter):
        """
        Reset for next block.
        """
        s = [0 for i in range(self.STATESIZE)]
        # Constant
        s[0:4] = bytes_to_int_list(b'expand 32-byte k')
        # Key
        s[4:12] = bytes_to_int_list(self._key)
        # Counter
        c = struct.pack('<Q', counter)
        s[12:14] = bytes_to_int_list(c)
        # Nonce
        s[14:16] = bytes_to_int_list(self._nonce)
        return s

    @staticmethod
    def _qr(a, b, c, d):
        a_, b_, c_, d_ = a, b, c, d
        # l1
        a_ = madd(a_, b_)
        d_ ^= a_
        d_ = rotl(d_, 16)
        # l2
        c_ = madd(c_, d_)
        b_ ^= c_
        b_ = rotl(b_, 12)
        # l3
        a_ = madd(a_, b_)
        d_ ^= a_
        d_ = rotl(d_, 8)
        # l4
        c_ = madd(c_, d_)
        b_ ^= c_
        b_ = rotl(b_, 7)
        return a_, b_, c_, d_

    @staticmethod
    def _round(x):
        indices = [
            # odd round
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            # even round
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14)
        ]
        y = x.copy()
        for (a, b, c, d) in indices:
            y[a], y[b], y[c], y[d] = ChaCha20._qr(y[a], y[b], y[c], y[d])
        return y

    def _block(self, counter):
        f = x = self._init(counter)
        for i in range(0, 20, 2):
            x = self._round(x)
        return list(map(lambda y: madd(y[0], y[1]), zip(x, f)))

    def keystream(self, n):
        to_gen = n - len(self._left)
        generated = 0
        while to_gen > generated:
            self._left += ints_to_bytes(self._block(self._counter))
            self._counter += 1
            generated += 4 * self.STATESIZE
        res = self._left[:n]
        self._left = self._left[n:]
        return res

    def crypt(self, data):
        ks = self.keystream(len(data))
        return bytes(map(lambda x: x[0] ^ x[1], zip(data, ks)))

    def encrypt(self, data):
        return self.crypt(data)

    def decrypt(self, data):
        return self.crypt(data)

    def set_counter(self, value):
        self._left = b''
        self._couter = value
