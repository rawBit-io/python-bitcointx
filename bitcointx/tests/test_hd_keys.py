# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

import unittest

from bitcointx.core import b2x, x
from bitcointx.core.key import (
    CExtKey, CExtPubKey, BIP32Path, BIP32_HARDENED_KEY_OFFSET
)
from bitcointx.wallet import CBitcoinExtKey, CBitcoinExtPubKey


BIP32_TEST_VECTORS = [
    [
        ["vector1", "000102030405060708090a0b0c0d0e0f"],
        ["xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
         "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
         0x80000000],
        ["xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
         "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
         1],
        ["xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
         "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
         0x80000002],
        ["xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
         "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
         2],
        ["xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
         "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
         1000000000],
        ["xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
         "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
         0]
    ],
    [
        ["vector2", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"],
        ["xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
         "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
         0],
        ["xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
         "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
         0xFFFFFFFF],
        ["xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
         "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
         1],
        ["xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
         "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
         0xFFFFFFFE],
        ["xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
         "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
         2],
        ["xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
         "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
         0]
    ],
    [
        ["vector3", "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"],
        ["xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
         "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
         0x80000000],
        ["xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
         "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
         0]
    ]
]


class Test_CBitcoinExtKey(unittest.TestCase):
    def test(self):
        def T(base58_xprivkey, expected_hex_xprivkey):
            key = CBitcoinExtKey(base58_xprivkey)
            self.assertEqual(b2x(key), expected_hex_xprivkey)
            key2 = CBitcoinExtKey.from_bytes(x(expected_hex_xprivkey))
            self.assertEqual(b2x(key), b2x(key2))

        T('xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
          '00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32')
        T('xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
          '025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93')

    def test_invalid_xprivkey(self):
        invalid_xpriv_str = 'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW'
        with self.assertRaises(ValueError):
            CBitcoinExtKey(invalid_xpriv_str)

        valid_xprivkey = CBitcoinExtKey('xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9')
        with self.assertRaises(ValueError):
            CExtKey(valid_xprivkey[:-1])  # short length

        with self.assertRaises(ValueError):
            CExtKey(valid_xprivkey + b'\x00')  # long length

    def test_from_xpriv(self):
        xpriv_str = 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
        xpriv = CBitcoinExtKey(xpriv_str)
        self.assertEqual(xpriv_str, str(CBitcoinExtKey.from_bytes(xpriv)))

    def test_invalid_derivation(self):
        xpriv = CBitcoinExtKey(
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        )

        with self.assertRaises(ValueError):
            xpriv.derive(1 << 32)

        final_xpriv_str = 'xprvJ9DiCzes6yvKjEy8duXR1Qg6Et6CBmrR4yFJvnburXG4X6VnKbNxoTYhvVdpsxkjdXwX3D2NJHFCAnnN1DdAJCVQitnFbFWv3fL3oB2BFo4'
        for _ in range(255):
            xpriv = xpriv.derive(0)
        self.assertEqual(str(CBitcoinExtKey.from_bytes(xpriv)), final_xpriv_str)

        with self.assertRaises(ValueError):
            xpriv.derive(0)  # depth > 255

    def test_standard_bip32_vectors(self):
        for vector in BIP32_TEST_VECTORS:
            _, seed = vector[0]
            base_key = CBitcoinExtKey.from_seed(x(seed))
            self.assertEqual(base_key.parent_fp, b'\x00\x00\x00\x00')
            key = base_key
            path = []
            for xpub, xpriv, child_num in vector[1:]:
                self.assertEqual(xpub, str(key.neuter()))
                self.assertEqual(xpriv, str(key))
                parent_fp = key.fingerprint
                key = key.derive(child_num)
                self.assertEqual(key.parent_fp, parent_fp)
                path.append(child_num)

            key_from_path = base_key.derive_path(str(BIP32Path(path)))
            self.assertEqual(key, key_from_path)


class Test_CBitcoinExtPubKey(unittest.TestCase):
    def test(self):
        def T(base58_xpubkey, expected_hex_xpubkey):
            key = CBitcoinExtPubKey(base58_xpubkey)
            self.assertEqual(b2x(key), expected_hex_xpubkey)
            key2 = CBitcoinExtPubKey.from_bytes(x(expected_hex_xpubkey))
            self.assertEqual(b2x(key), b2x(key2))

        T('xpub661MyMwAqRbcFMfe2ZGFSPef9xMXWrZUDta7RXKPbtxuNyepg8ewAWVV5qME4omB67Ek4eDrpyFtMcUcznxCf8sV8DCnsZeWj6Z2N3RXqPo',
          '00000000000000000051cba4db213938e74101b4264be4f45a9f3a7b2c0005963331c7a0ffaa5978b903782da1cfa3f03b9ae2bfa3077296410f5f80cf92eaa2f87d738a320b8486f326')
        T('xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
          '025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b')

    def test_derive(self):
        def T(base_xpub, expected_child, path):
            xpub = CBitcoinExtPubKey(base_xpub)
            self.assertEqual(xpub.parent_fp, b'\x00\x00\x00\x00')
            for child_num in path:
                parent_fp = xpub.fingerprint
                xpub = xpub.derive(child_num)
                self.assertEqual(xpub.parent_fp, parent_fp)

            self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), expected_child)

            xpub = CBitcoinExtPubKey(base_xpub).derive_path(str(BIP32Path(path)))
            self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), expected_child)

        T('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
          'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
          [0])

        T('xpub661MyMwAqRbcG2veuy7DxC7yfKodTbY46UKYgnrERu9WADL5pBjRzthJtxMpWYeofw5rHWtemkgJAcSCup19Vorze6H3etYGbiEU4MumRV7',
          'xpub6E6u1x8dM8qBkicTyJnnM3wYfbYSfsnRPYgNXTkD1PqF2AVasRGPckvaewHDzErwSMG9HhvcEc1QYHeGGp8pybcQr2RSXcGBs9YrcJ83NEo',
          [0, 1, 88430, 42])

    def test_invalid_xpubkey(self):
        invalid_xpub_str = 'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdcaHQwzT'
        with self.assertRaises(ValueError):
            CBitcoinExtPubKey(invalid_xpub_str)

        valid_xpubkey = CBitcoinExtPubKey('xpub661MyMwAqRbcG2veuy7DxC7yfKodTbY46UKYgnrERu9WADL5pBjRzthJtxMpWYeofw5rHWtemkgJAcSCup19Vorze6H3etYGbiEU4MumRV7')
        with self.assertRaises(ValueError):
            CExtPubKey(valid_xpubkey[:-1])  # short length

        with self.assertRaises(ValueError):
            CExtPubKey(valid_xpubkey + b'\x00')  # long length

    def test_from_xpub(self):
        xpub_str = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub = CBitcoinExtPubKey(xpub_str)
        self.assertEqual(xpub_str, str(CBitcoinExtPubKey.from_bytes(xpub)))

    def test_invalid_derivation(self):
        xpub = CBitcoinExtPubKey(
            'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        )

        with self.assertRaises(ValueError):
            xpub.derive(BIP32_HARDENED_KEY_OFFSET)

        final_xpub_str = 'xpubEPPCAoZp7t6CN5GGoyYTEr91FCaPpQonRouneRKmRCzgfcWNHnyHMuQPCDn8wLv1vYyPrFpSK26VeA9dDXTKMCLm7FaSY9aVTWw5mTZLC7F'
        for _ in range(255):
            xpub = xpub.derive(0)
        self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), final_xpub_str)

        with self.assertRaises(ValueError):
            xpub.derive(0)  # depth > 255


class Test_CExtPubKey(unittest.TestCase):
    def test(self):
        xpub_str = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub = CBitcoinExtPubKey(xpub_str)
        xpub2 = CExtPubKey(xpub)
        self.assertEqual(xpub_str, str(CBitcoinExtPubKey.from_bytes(xpub2)))
        self.assertEqual(xpub, CBitcoinExtPubKey.from_bytes(xpub2))
        self.assertEqual(xpub.derive(0), xpub2.derive(0))


class Test_CExtKey(unittest.TestCase):
    def test_extkey(self):
        xprv_str = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        xprv = CBitcoinExtKey(xprv_str)
        xprv2 = CExtKey(xprv)
        self.assertEqual(xprv_str, str(CBitcoinExtKey.from_bytes(xprv2)))
        self.assertEqual(bytes(xprv.derive(BIP32_HARDENED_KEY_OFFSET)),
                         bytes(xprv2.derive(BIP32_HARDENED_KEY_OFFSET)))
        self.assertEqual(str(xprv.neuter()), str(CBitcoinExtPubKey.from_bytes(xprv2.neuter())))


class Test_BIP32Path(unittest.TestCase):
    def test_from_string(self):
        with self.assertRaises(ValueError):
            BIP32Path('')  # empty path that is not 'm'
        with self.assertRaises(ValueError):
            BIP32Path('m/')  # empty path that is not 'm'
        with self.assertRaises(ValueError):
            BIP32Path('/')
        with self.assertRaises(ValueError):
            BIP32Path('nonsense')
        with self.assertRaises(ValueError):
            BIP32Path('m/-1')
        with self.assertRaises(ValueError):
            BIP32Path('m/4/')  # slash at the end of the path
        with self.assertRaises(ValueError):
            BIP32Path("m/4h/1'")  # inconsistent use of markers
        with self.assertRaises(ValueError):
            BIP32Path("m/2147483648'/1'")  # hardened index too big
        with self.assertRaises(ValueError):
            BIP32Path("m/2147483648/1")  # non-hardened index too big
        with self.assertRaises(ValueError):
            # wrong markers
            BIP32Path("m/2147483647'/1'/0", hardened_marker='h')
        with self.assertRaises(ValueError):
            # wrong markers
            BIP32Path("m/2147483647h/1h/0", hardened_marker="'")
        with self.assertRaises(ValueError):
            # invalid marker
            BIP32Path("m/2147483647h/1h/0", hardened_marker="?")
        with self.assertRaises(ValueError):
            # too long path
            BIP32Path('m/'+'/'.join('0' for _ in range(256)))

        self.assertEqual(list(BIP32Path('m/0')), [0])
        self.assertEqual(list(BIP32Path('m')), [])

        self.assertEqual(list(BIP32Path("m/4h/5/1h")),
                         [4+BIP32_HARDENED_KEY_OFFSET, 5,
                          1+BIP32_HARDENED_KEY_OFFSET])

        # check that markers correctly picked up from the string
        self.assertEqual(str(BIP32Path("m/4h/5h/1/4")), "m/4h/5h/1/4")
        self.assertEqual(str(BIP32Path("m/4'/5'/1/4")), "m/4'/5'/1/4")

        self.assertEqual(list(BIP32Path("m/0'/2147483647'/1/10")),
                         [BIP32_HARDENED_KEY_OFFSET, 0xFFFFFFFF, 1, 10])

        self.assertEqual(
            list(BIP32Path(
                'm/'+'/'.join("%u'" % n for n in range(128))
                + '/' + '/'.join("%u" % (BIP32_HARDENED_KEY_OFFSET-n-1)
                                 for n in range(127)))),
            [n+BIP32_HARDENED_KEY_OFFSET for n in range(128)]
            + [BIP32_HARDENED_KEY_OFFSET-n-1 for n in range(127)])

    def test_from_list(self):
        with self.assertRaises(ValueError):
            BIP32Path([-1])
        with self.assertRaises(ValueError):
            BIP32Path([0xFFFFFFFF+1])  # more than 32bit
        with self.assertRaises(ValueError):
            # only apostrophe and "h" markers are allowed
            BIP32Path([0xFFFFFFFF, 0, 0x80000000],
                      hardened_marker='b')

        with self.assertRaises(ValueError):
            # too long path
            BIP32Path([0 for _ in range(256)])

        self.assertEqual(str(BIP32Path([0])), "m/0")
        self.assertEqual(str(BIP32Path([])), "m")

        self.assertEqual(
            str(BIP32Path([0xFFFFFFFF, 0x80000001, 1, 0x80000002])),
            "m/2147483647'/1'/1/2'")

        self.assertEqual(
            str(BIP32Path([0xFFFFFFFF, 0x80000001, 1, 2],
                          hardened_marker='h')),
            "m/2147483647h/1h/1/2")

        self.assertEqual(
            str(BIP32Path([n+BIP32_HARDENED_KEY_OFFSET for n in range(128)]
                          + [n for n in range(127)])),
            'm/'+'/'.join("%u'" % n for n in range(128))
            + '/' + '/'.join("%u" % n for n in range(127)))

    def test_from_BIP32Path(self):
        p = BIP32Path("m/4h/5h/1/4")
        self.assertEqual(str(BIP32Path(p)), "m/4h/5h/1/4")
        self.assertEqual(str(BIP32Path(p, hardened_marker="'")), "m/4'/5'/1/4")
        p = BIP32Path("m/4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p)), "m/4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p, hardened_marker='h')), "m/4h/5h/1/4")

    def test_random_access(self):
        p = BIP32Path("m/4h/5h/1/4")
        self.assertEqual(p[0], 4+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(p[1], 5+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(p[2], 1)
        self.assertEqual(p[3], 4)
        p = BIP32Path([0xFFFFFFFF-n for n in range(255)])
        self.assertEqual(p[254], 0xFFFFFF01)
