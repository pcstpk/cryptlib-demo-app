import os
from typing import Tuple

from cryptlib.algorithms.ecdh import ECDH as CryptlibECDH
from cryptlib.algorithms.kyber_kem import KyberKEM
from cryptlib.core.ecc_parameters import get_curve
from cryptlib.core.ecc_math import Point

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoAdapter:
    """Adapter that uses `cryptlib` for ECDH and Kyber operations and `cryptography` for AEAD/HKDF."""

    def __init__(self, algorithm: str = 'ECDH', curve_name: str = 'P-256', kyber_variant: str = 'Kyber-512'):
        self.algorithm = algorithm.upper()
        self.curve_name = curve_name
        self.kyber_variant = kyber_variant
        self._sk = None
        self._priv_scalar = None

        if self.algorithm == 'KYBER':
            self._backend = KyberKEM(variant=kyber_variant)
        else:
            self._backend = CryptlibECDH(curve_name)
            # get curve params for point size
            self._curve_params = get_curve(curve_name)
            self._size = (self._curve_params.n.bit_length() + 7) // 8

    def _serialize_point(self, point: Point) -> bytes:
        xb = int(point.x).to_bytes(self._size, 'big')
        yb = int(point.y).to_bytes(self._size, 'big')
        return b'\x04' + xb + yb

    def _parse_point(self, data: bytes) -> Point:
        if data[0] != 4:
            raise ValueError('only uncompressed points supported')
        xb = int.from_bytes(data[1:1 + self._size], 'big')
        yb = int.from_bytes(data[1 + self._size:1 + 2 * self._size], 'big')
        return Point(xb, yb)

    # Asymmetric APIs
    def generate_keypair(self) -> bytes:
        if self.algorithm == 'KYBER':
            pk, sk = self._backend.generate_keypair()
            self._sk = sk
            return pk
        else:
            kp = self._backend.generate_keypair()
            # cryptlib ECDH returns (Point, scalar)
            pub_point, priv_scalar = kp
            self._priv_scalar = priv_scalar
            return self._serialize_point(pub_point)

    def derive_shared_secret(self, peer_pub: bytes) -> bytes:
        if self.algorithm == 'KYBER':
            raise RuntimeError('derive_shared_secret not valid for KYBER; use encapsulate/decapsulate')
        peer_point = self._parse_point(peer_pub)
        if not self._backend.curve.is_on_curve(peer_point):
            raise RuntimeError('Received invalid peer public key, not on curve')
        # cryptlib ECDH derive_shared_secret(private_scalar, peer_public_point)
        shared = self._backend.derive_shared_secret(self._priv_scalar, peer_point)
        # shared may be an int or bytes; normalize to bytes
        if isinstance(shared, int):
            # encode to fixed size
            return int(shared).to_bytes(self._size, 'big')
        return bytes(shared)

    def encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        if self.algorithm != 'KYBER':
            raise RuntimeError('encapsulate only valid for KYBER')
        ct, shared = self._backend.encapsulate(pk)
        return ct, shared

    def decapsulate(self, ct: bytes) -> bytes:
        if self.algorithm != 'KYBER':
            raise RuntimeError('decapsulate only valid for KYBER')
        shared = self._backend.decapsulate(self._sk, ct)
        return shared

    # AEAD helpers (use cryptography)
    def derive_aead(self, shared_secret: bytes) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data')
        return hkdf.derive(shared_secret)

    def aead_encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ct

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
