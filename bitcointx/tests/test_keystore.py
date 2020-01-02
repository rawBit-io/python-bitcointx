# Copyright (C) 2019 The python-bitcointx developers
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

from bitcointx.core import x
from bitcointx.core.key import CPubKey, KeyStore, BIP32Path, KeyDerivationInfo
from bitcointx.wallet import CCoinKey, CCoinExtKey, CCoinExtPubKey


class Test_KeyStore(unittest.TestCase):
    def test(self):
        xpriv1 = CCoinExtKey('xprv9s21ZrQH143K4TFwadu5VoGfAChTWXUw49YyTWE8SRqC9ZC9AQpHspzgbAcScTmC4MURiMT7pmCbci5oKbWijJmARiUeRiLXYehCtsoVdYf')
        xpriv2 = CCoinExtKey('xprv9uZ4jKNZFfGEQTTunEuy2cLQMckzuy5saCmiKuxYJgHX5pGFCx3KQ8mTkSfuLNaWGNQ9LKCg5YzUihxoQv493ErnkcaS3q1udx9X8WZbwZc')
        priv1 = CCoinKey('L27zAtDgjDC34sG5ZSey1wvdZ9JyZsNnvZEwbbZYWUYXXQtgri5R')
        xpub1 = CCoinExtPubKey('xpub69b6hm71WMe1PGpgUmaDPkbxYoTzpmswX8KGeinv7SPRcKT22RdMM4416kqtEUuXqXCAi7oGx7tHwCRTd3JHatE3WX1Zms6Lgj5mrbFyuro')
        xpub1.assign_derivation_info(KeyDerivationInfo(xpub1.parent_fp, BIP32Path('m/0')))
        pub1 = CPubKey(x('03b0fe9cfc88fed9fcecf9dcb7bb5c90dd1a4500f4cfc5c854ffc8e54d639d6bc5'))

        kstore = KeyStore(
            external_privkey_lookup=(
                lambda key_id, dinfo: priv1 if key_id == priv1.pub.key_id
                else None),
            external_pubkey_lookup=(
                lambda key_id, dinfo: pub1 if key_id == pub1.key_id
                else None)
        )
        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), priv1)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), pub1)
        self.assertEqual(kstore.get_pubkey(priv1.pub.key_id), priv1.pub)

        kstore = KeyStore(xpriv1, priv1, xpub1, pub1)
        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), priv1)
        self.assertEqual(kstore.get_pubkey(priv1.pub.key_id), priv1.pub)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), pub1)

        # check no-derivation lookup for (priv, pub) of extended keys
        self.assertEqual(kstore.get_privkey(xpriv1.pub.key_id), xpriv1.priv)
        self.assertEqual(
            kstore.get_privkey(xpriv1.pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m"))),
            xpriv1.priv)
        self.assertEqual(kstore.get_pubkey(xpriv1.pub.key_id), xpriv1.pub)
        self.assertEqual(
            kstore.get_pubkey(xpriv1.pub.key_id,
                              KeyDerivationInfo(xpriv1.fingerprint,
                                                BIP32Path("m"))),
            xpriv1.pub)

        # can find xpub1's pub without derivation
        self.assertEqual(kstore.get_pubkey(xpub1.pub.key_id), xpub1.pub)

        # and with derivation info supplied
        self.assertEqual(
            kstore.get_pubkey(xpub1.pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path("m/0"))),
            xpub1.pub)

        # but not with incorrect derivation info
        self.assertEqual(
            kstore.get_pubkey(xpub1.pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path("m"))),
            None)

        # check longer derivations
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id),
            None)
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m/0'/1'/2'"))),
            xpriv1.derive_path("0'/1'/2'").priv)
        self.assertEqual(
            kstore.get_pubkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                              KeyDerivationInfo(xpriv1.fingerprint,
                                                BIP32Path("m/0'/1'/2'"))),
            xpriv1.derive_path("0'/1'/2'").pub)

        self.assertEqual(
            kstore.get_pubkey(xpub1.derive_path("0/1/2").pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path('m/0/0/1/2'))),
            xpub1.derive_path("0/1/2").pub)

        path = BIP32Path("0'/1'/2'")
        derived_xpub = xpriv2.derive_path(path).neuter()
        derived_pub = derived_xpub.derive_path('3/4/5').pub
        self.assertEqual(kstore.get_pubkey(derived_pub.key_id), None)
        kstore.add_key(derived_xpub)
        self.assertEqual(
            kstore.get_pubkey(
                derived_pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp, BIP32Path("m/0/0'/1'/2'/3/4/5"))),
            derived_pub)

        kstore.add_key(xpriv2)

        derived_pub = xpriv2.derive_path('3h/4h/5h').pub
        self.assertEqual(
            kstore.get_pubkey(
                derived_pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp,
                                  BIP32Path("m/0/3'/4'/5'"))),
            derived_pub)

        derived_priv = xpriv2.derive_path('3h/4h/5h').priv
        self.assertEqual(
            kstore.get_privkey(
                derived_priv.pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp,
                                  BIP32Path("m/0/3'/4'/5'"))),
            derived_priv)

        # check that .remove_key() works
        for k in (xpriv1, priv1, xpub1, pub1):
            kstore.remove_key(k)

        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), None)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), None)
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m/0'/1'/2'"))),
            None)
        self.assertEqual(
            kstore.get_pubkey(xpub1.derive_path("0/1/2").pub.key_id),
            None)
