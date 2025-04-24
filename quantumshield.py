import base64
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mlkem_facade import MLKEMFacade  # Assumes mlkem_facade.py from QuantumShield

class QuantumShield:
    """QuantumShield SDK for post-quantum cryptography with ML-KEM."""
    
    def __init__(self, parameter_set="512"):
        print("QuantumShield: Starting initialization")
        self.parameter_set = parameter_set
        print("QuantumShield: Creating MLKEMFacade")
        self.facade = MLKEMFacade()
        print("QuantumShield: MLKEMFacade created")

    def generate_keypair(self):
        """Generate ML-KEM key pair, return public/private keys in PEM format."""
        key_pair = self.facade.generate_keypair(parameter_set=self.parameter_set)
        public_pem = key_pair.public_key.to_pem()
        private_pem = key_pair.private_key.to_pem()        
        return public_pem, private_pem

    def encapsulate(self, public_key_pem):
        """Encapsulate a shared secret using public key, return ciphertext and secret."""
        public_key = self.facade.MLKEMPublicKey.from_pem(public_key_pem)
        ciphertext, shared_secret = self.facade.encapsulate(public_key)
        ciphertext_b64 = base64.b64encode(ciphertext.ciphertext_bytes).decode()
        return ciphertext_b64, shared_secret

    def decapsulate(self, private_key_pem, ciphertext_b64):
        """Decapsulate ciphertext using private key, return shared secret."""
        private_key = self.facade.MLKEMPrivateKey.from_pem(private_key_pem)
        ciphertext = self.facade.MLKEMCiphertext.from_base64(ciphertext_b64, parameter_set=self.parameter_set)
        shared_secret = self.facade.decapsulate(private_key, ciphertext)
        return shared_secret

    def hybrid_encrypt(self, data, public_key_pem):
        """Encrypt data with AES-256-GCM using ML-KEM-derived key."""
        ciphertext_b64, shared_secret = self.encapsulate(public_key_pem)
        # Derive AES key from shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"QuantumShield",
        )
        aes_key = hkdf.derive(shared_secret)
        # Encrypt data
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        tag = encryptor.tag
        return {
            "mlkem_ciphertext": ciphertext_b64,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

    def hybrid_decrypt(self, private_key_pem, encrypted_data):
        """Decrypt AES-256-GCM data using ML-KEM-derived key."""
        shared_secret = self.decapsulate(
            private_key_pem, encrypted_data["mlkem_ciphertext"]
        )
        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"QuantumShield",
        )
        aes_key = hkdf.derive(shared_secret)
        # Decrypt data
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()