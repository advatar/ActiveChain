import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import receiver as r


def jwt(payload, key, typ):
    raw = r.b64(json.dumps({'alg': 'ES256', 'typ': typ}).encode()) + '.' + r.b64(json.dumps(payload).encode())
    a, b = decode_dss_signature(key.sign(raw.encode(), ec.ECDSA(hashes.SHA256())))
    return raw + '.' + r.b64(a.to_bytes(32, 'big') + b.to_bytes(32, 'big'))


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'state.sqlite'
        self.fixtures = Path(__file__).parent / 'fixtures'
        self.receiver = r.Receiver(self.path, self.fixtures)
        self.session = self.receiver.create({'owner': 'ab' * 48, 'chain': 'cd' * 48})
        self.nonce = r.unpack(r.unb64(self.receiver.request(self.session['id']).split('.')[1]))['nonce']

    def tearDown(self):
        self.receiver.db.close()
        self.directory.cleanup()

    def presentation(self, nonce=None):
        holder = ec.generate_private_key(ec.SECP256R1())
        public = holder.public_key().public_numbers()
        disclosure = r.b64(json.dumps(['random-salt', 'age_over_18', True]).encode())
        issuer = jwt({'iss': 'https://issuer.example', 'vct': r.VCT, 'iat': r.EPOCH, 'exp': r.EPOCH + 300,
                      '_sd_alg': 'sha-256', '_sd': [r.b64(hashlib.sha256(disclosure.encode()).digest())],
                      'cnf': {'jwk': {'kty': 'EC', 'crv': 'P-256', 'x': r.b64(public.x.to_bytes(32, 'big')), 'y': r.b64(public.y.to_bytes(32, 'big'))}}}, self.receiver.key, 'dc+sd-jwt')
        base = issuer + '~' + disclosure + '~'
        return base + jwt({'aud': 'rp.example', 'iat': r.EPOCH, 'nonce': nonce or self.nonce,
                           'sd_hash': r.b64(hashlib.sha256(base.encode()).digest())}, holder, 'kb+jwt')

    def respond(self, vp):
        return self.receiver.respond(urlencode({'state': self.session['id'], 'vp_token': json.dumps({'identity': [vp]})}).encode())

    def status(self):
        return self.receiver.status(self.session['id'], self.session['token'])

    def test_real_signatures_roundtrip_restart_and_no_personal_storage(self):
        vp = self.presentation()
        self.assertTrue(self.respond(vp)['redirect_uri'].startswith('activechain-wallet://identity-return?session='))
        self.assertEqual(self.status()['status'], 'test_verified')
        self.assertEqual(self.status()['assurance'], 'test_only')
        self.receiver.db.close()
        self.receiver = r.Receiver(self.path, self.fixtures)
        self.assertEqual(self.status()['status'], 'test_verified')
        with self.assertRaises(ValueError):
            self.respond(vp)
        self.assertNotIn(vp.encode(), self.path.read_bytes())
        self.assertNotIn(b'age_over_18', self.path.read_bytes())

    def test_substituted_nonce_cannot_attach(self):
        self.respond(self.presentation('another-request'))
        self.assertEqual(self.status()['status'], 'rejected')
        self.assertEqual(self.status()['proof'], '')

    def test_decline_is_consumed_and_receipt_requires_private_token(self):
        self.receiver.respond(urlencode({'state': self.session['id'], 'error': 'access_denied'}).encode())
        self.assertEqual(self.status()['status'], 'declined')
        with self.assertRaises(ValueError):
            self.receiver.status(self.session['id'], 'wrong')
        with self.assertRaises(ValueError):
            self.respond(self.presentation())

    def test_invalid_encoding_duplicate_state_and_expiry(self):
        for body in [b'state=%XX', b'state=a&state=b', b'state=x&unknown=x']:
            with self.assertRaises(ValueError):
                self.receiver.respond(body)
        self.receiver.db.execute('UPDATE sessions SET expires=0')
        self.receiver.db.commit()
        self.assertEqual(self.status()['status'], 'expired')
        with self.assertRaises(ValueError):
            self.respond(self.presentation())

    def test_tampered_signature(self):
        vp = self.presentation()
        parts = vp.rsplit('.', 1)
        signature = bytearray(r.unb64(parts[1])); signature[0] ^= 1
        self.respond(parts[0] + '.' + r.b64(signature))
        self.assertEqual(self.status()['status'], 'rejected')

if __name__ == '__main__':
    unittest.main()
