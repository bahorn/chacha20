"""
Test suite
"""
import unittest
import binascii
import secrets
from chacha20 import ChaCha20


def encrypt_decrypt_pair_test(key, nonce, counter=(100, 100)):
    a = ChaCha20(
        key=binascii.unhexlify(key),
        nonce=binascii.unhexlify(nonce),
        counter=counter[0]
    )

    b = ChaCha20(
        key=binascii.unhexlify(key),
        nonce=binascii.unhexlify(nonce),
        counter=counter[1]
    )
    test = secrets.token_bytes(10003)
    v = a.encrypt(test)
    return test, b.decrypt(v)


def testcase(key, nonce, keystream):
    # Test keystream generation
    a = ChaCha20(
        key=binascii.unhexlify(key),
        nonce=binascii.unhexlify(nonce)
    )
    ks = binascii.unhexlify(keystream)
    gs = a.keystream(len(ks))
    if ks != gs:
        return False

    # Test Decryption Sucess
    i, j = encrypt_decrypt_pair_test(key, nonce, counter=(100, 100))
    if i != j:
        return False
    # Test Decryption Failure
    i, j = encrypt_decrypt_pair_test(key, nonce, counter=(100, 101))
    if i == j:
        return False
    return True


class TestChaCha20(unittest.TestCase):
    def test_known(self):
        """
        From the IETF draft:
        https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-04#section-7
        """
        self.assertTrue(testcase(
            key=b'0000000000000000000000000000000000000000000000000000000000000000',
            nonce=b'0000000000000000',
            keystream=b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
        ))
        self.assertTrue(testcase(
            key=b'0000000000000000000000000000000000000000000000000000000000000001',
            nonce=b'0000000000000000',
            keystream=b'4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963'
        ))
        self.assertTrue(testcase(
            key=b'0000000000000000000000000000000000000000000000000000000000000000',
            nonce=b'0000000000000001',
            keystream=b'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'
        ))
        self.assertTrue(testcase(
            key=b'0000000000000000000000000000000000000000000000000000000000000000',
            nonce=b'0100000000000000',
            keystream=b'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b'
        ))
        self.assertTrue(testcase(
            key=b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            nonce=b'0001020304050607',
            keystream=b'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9'
        ))

    def test_validate_sizes(self):
        for i in range(0, 32):
            with self.assertRaises(Exception):
                testcase(
                    key=b'00'*i,
                    nonce=b'0000000000000000',
                    keystream=b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
                )
        for i in range(33, 64):
            with self.assertRaises(Exception):
                testcase(
                    key=b'00'*i,
                    nonce=b'0000000000000000',
                    keystream=b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
                )
        for i in range(0, 8):
            with self.assertRaises(Exception):
                testcase(
                    key=b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                    nonce=b'00'*i,
                    keystream=b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
                )
        for i in range(9, 64):
            with self.assertRaises(Exception):
                testcase(
                    key=b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                    nonce=b'00'*i,
                    keystream=b'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
                )



if __name__ == "__main__":
    unittest.main()
