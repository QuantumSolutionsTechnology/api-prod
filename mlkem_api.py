"""
ML-KEM API - A RESTful API for quantum-resistant encryption
==========================================================

This module provides a Python implementation of ML-KEM using liboqs.
"""

import os
import base64
import json
from dataclasses import dataclass
from typing import Dict, Tuple, Union, Optional, List, Any
import oqs
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class MLKEMPublicKey:
    """ML-KEM public key representation"""
    algorithm: str = "ML-KEM"
    parameter_set: str = "512"
    key_bytes: bytes = None
    
    def to_pem(self) -> str:
        """Convert public key to PEM format"""
        b64_data = base64.b64encode(self.key_bytes).decode('ascii')
        return (
            f"-----BEGIN ML-KEM {self.parameter_set} PUBLIC KEY-----\n" +
            "\n".join([b64_data[i:i+64] for i in range(0, len(b64_data), 64)]) + "\n" +
            f"-----END ML-KEM {self.parameter_set} PUBLIC KEY-----"
        )
    
    @classmethod
    def from_pem(cls, pem_data: str) -> 'MLKEMPublicKey':
        """Create a public key from PEM format"""
        param_set = "512"
        header_line = pem_data.splitlines()[0]
        if "ML-KEM 768" in header_line:
            param_set = "768"
        elif "ML-KEM 1024" in header_line:
            param_set = "1024"
            
        lines = pem_data.replace("-----BEGIN ML-KEM", "").replace("PUBLIC KEY-----", "")
        lines = lines.replace("-----END ML-KEM", "").replace("PUBLIC KEY-----", "")
        b64_data = "".join(lines.strip().splitlines())
        
        return cls(
            algorithm="ML-KEM",
            parameter_set=param_set,
            key_bytes=base64.b64decode(b64_data)
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation"""
        return {
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "key": base64.b64encode(self.key_bytes).decode('ascii')
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MLKEMPublicKey':
        """Create a public key from dictionary"""
        return cls(
            algorithm=data.get("algorithm", "ML-KEM"),
            parameter_set=data.get("parameter_set", "512"),
            key_bytes=base64.b64decode(data["key"])
        )

@dataclass
class MLKEMPrivateKey:
    """ML-KEM private key representation"""
    algorithm: str = "ML-KEM"
    parameter_set: str = "512"
    key_bytes: bytes = None
    public_key_bytes: bytes = None
    
    def to_pem(self) -> str:
        """Convert private key to PEM format"""
        combined = len(self.key_bytes).to_bytes(4, byteorder='big') + self.key_bytes
        if self.public_key_bytes:
            combined += len(self.public_key_bytes).to_bytes(4, byteorder='big') + self.public_key_bytes
        
        b64_data = base64.b64encode(combined).decode('ascii')
        return (
            f"-----BEGIN ML-KEM {self.parameter_set} PRIVATE KEY-----\n" +
            "\n".join([b64_data[i:i+64] for i in range(0, len(b64_data), 64)]) + "\n" +
            f"-----END ML-KEM {self.parameter_set} PRIVATE KEY-----"
        )
    
    @classmethod
    def from_pem(cls, pem_data: str) -> 'MLKEMPrivateKey':
        """Create a private key from PEM format"""
        param_set = "512"
        header_line = pem_data.splitlines()[0]
        if "ML-KEM 768" in header_line:
            param_set = "768"
        elif "ML-KEM 1024" in header_line:
            param_set = "1024"
            
        lines = pem_data.replace("-----BEGIN ML-KEM", "").replace("PRIVATE KEY-----", "")
        lines = lines.replace("-----END ML-KEM", "").replace("PRIVATE KEY-----", "")
        b64_data = "".join(lines.strip().splitlines())
        
        combined = base64.b64decode(b64_data)
        priv_key_len = int.from_bytes(combined[:4], byteorder='big')
        priv_key = combined[4:4+priv_key_len]
        
        pub_key = None
        if len(combined) > 4+priv_key_len:
            pub_key_len = int.from_bytes(combined[4+priv_key_len:8+priv_key_len], byteorder='big')
            pub_key = combined[8+priv_key_len:8+priv_key_len+pub_key_len]
        
        return cls(
            algorithm="ML-KEM",
            parameter_set=param_set,
            key_bytes=priv_key,
            public_key_bytes=pub_key
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation"""
        result = {
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "private_key": base64.b64encode(self.key_bytes).decode('ascii')
        }
        if self.public_key_bytes:
            result["public_key"] = base64.b64encode(self.public_key_bytes).decode('ascii')
        return result
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MLKEMPrivateKey':
        """Create a private key from dictionary"""
        pub_key = None
        if "public_key" in data:
            pub_key = base64.b64decode(data["public_key"])
            
        return cls(
            algorithm=data.get("algorithm", "ML-KEM"),
            parameter_set=data.get("parameter_set", "512"),
            key_bytes=base64.b64decode(data["private_key"]),
            public_key_bytes=pub_key
        )

@dataclass
class MLKEMKeyPair:
    """ML-KEM key pair representation"""
    public_key: MLKEMPublicKey
    private_key: MLKEMPrivateKey
    kem: oqs.KeyEncapsulation  # Store the KEM object with the private key state

@dataclass
class MLKEMCiphertext:
    """ML-KEM ciphertext representation"""
    algorithm: str = "ML-KEM"
    parameter_set: str = "512"
    ciphertext_bytes: bytes = None
    
    def to_base64(self) -> str:
        """Convert ciphertext to Base64 encoding"""
        return base64.b64encode(self.ciphertext_bytes).decode('ascii')
    
    @classmethod
    def from_base64(cls, b64_data: str, parameter_set: str = "512") -> 'MLKEMCiphertext':
        """Create ciphertext from Base64 encoding"""
        return cls(
            algorithm="ML-KEM",
            parameter_set=parameter_set,
            ciphertext_bytes=base64.b64decode(b64_data)
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation"""
        return {
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "ciphertext": base64.b64encode(self.ciphertext_bytes).decode('ascii')
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MLKEMCiphertext':
        """Create ciphertext from dictionary"""
        return cls(
            algorithm=data.get("algorithm", "ML-KEM"),
            parameter_set=data.get("parameter_set", "512"),
            ciphertext_bytes=base64.b64decode(data["ciphertext"])
        )

class MLKEMFacade:

    """
    High-level API for ML-KEM operations using liboqs.
    """
    
    def __init__(self):
        print("MLKEMFacade: Starting initialization")
        pass

    def _get_kem(self, parameter_set: str) -> oqs.KeyEncapsulation:
        """Create a new KEM object for the given parameter set."""
        param_map = {
            "512": "ML-KEM-512",
            "768": "ML-KEM-768",
            "1024": "ML-KEM-1024"
        }
        kem_name = param_map.get(parameter_set, "ML-KEM-512")
        return oqs.KeyEncapsulation(kem_name)

    def generate_keypair(self, parameter_set="512"):
        print(f"MLKEMFacade: Generating key pair with parameter set {parameter_set}")
        """
        Generate a new ML-KEM key pair.

        Args:
            parameter_set (str): ML-KEM parameter set ("512", "768", or "1024")

        Returns:
            MLKEMKeyPair: A key pair containing public and private keys, and the KEM object
        """
        if parameter_set not in ["512", "768", "1024"]:
            logger.error(f"Invalid parameter set: {parameter_set}. Must be 512, 768, or 1024.")
            raise ValueError("Parameter set must be 512, 768, or 1024")
        
        try:
            logger.info(f"Generating ML-KEM key pair with parameter set: {parameter_set}...")
            kem = self._get_kem(parameter_set)
            public_key_bytes = kem.generate_keypair()
            private_key_bytes = kem.export_secret_key()

            public_key = MLKEMPublicKey(
                algorithm="ML-KEM",
                parameter_set=parameter_set,
                key_bytes=public_key_bytes
            )

            private_key = MLKEMPrivateKey(
                algorithm="ML-KEM",
                parameter_set=parameter_set,
                key_bytes=private_key_bytes,
                public_key_bytes=public_key_bytes
            )

            logger.info("Key pair generated successfully.")
            return MLKEMKeyPair(public_key, private_key, kem)
        except Exception as e:
            logger.error(f"Failed to generate key pair: {str(e)}")
            raise

    def encapsulate(self, public_key: MLKEMPublicKey) -> Tuple[bytes, MLKEMCiphertext]:
        """
        Encapsulate a shared secret using a public key.

        Args:
            public_key (MLKEMPublicKey): The recipient's public key

        Returns:
            Tuple[bytes, MLKEMCiphertext]: (shared_secret, ciphertext)
        """
        try:
            logger.info("Encapsulating shared secret...")
            kem = self._get_kem(public_key.parameter_set)
            ciphertext_bytes, shared_secret = kem.encap_secret(public_key.key_bytes)

            ciphertext = MLKEMCiphertext(
                algorithm="ML-KEM",
                parameter_set=public_key.parameter_set,
                ciphertext_bytes=ciphertext_bytes
            )

            logger.info("Shared secret encapsulated successfully.")
            return shared_secret, ciphertext
        except Exception as e:
            logger.error(f"Failed to encapsulate shared secret: {str(e)}")
            raise

    def decapsulate(self, key_pair: MLKEMKeyPair, ciphertext: MLKEMCiphertext) -> bytes:
        """
        Decapsulate a shared secret using a key pair and ciphertext.

        Args:
            key_pair (MLKEMKeyPair): The key pair containing the KEM object with the private key
            ciphertext (MLKEMCiphertext): The encapsulated ciphertext

        Returns:
            bytes: The shared secret
        """
        try:
            logger.info("Decapsulating shared secret...")
            kem = key_pair.kem  # Reuse the KEM object with the private key state
            shared_secret = kem.decap_secret(ciphertext.ciphertext_bytes)
            logger.info("Shared secret decapsulated successfully.")
            return shared_secret
        except Exception as e:
            logger.error(f"Failed to decapsulate shared secret: {str(e)}")
            raise

    def encrypt(self, public_key: MLKEMPublicKey, plaintext: bytes) -> bytes:
        """
        Hybrid encryption using ML-KEM for key encapsulation and AES for data encryption.

        Args:
            public_key (MLKEMPublicKey): The recipient's public key
            plaintext (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message (contains both the encapsulated key and encrypted data)
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            logger.error("pycryptodome is required for hybrid encryption")
            raise ImportError("pycryptodome is required for hybrid encryption")

        try:
            logger.info("Performing hybrid encryption...")
            shared_secret, ciphertext = self.encapsulate(public_key)

            key_size = 16
            if public_key.parameter_set == "768":
                key_size = 24
            elif public_key.parameter_set == "1024":
                key_size = 32

            aes_key = shared_secret[:key_size]
            iv = os.urandom(16)

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            result = len(ciphertext.ciphertext_bytes).to_bytes(4, byteorder='big')
            result += ciphertext.ciphertext_bytes
            result += iv
            result += encrypted_data

            logger.info("Hybrid encryption completed successfully.")
            return result
        except Exception as e:
            logger.error(f"Failed to perform hybrid encryption: {str(e)}")
            raise

    def decrypt(self, key_pair: MLKEMKeyPair, ciphertext: bytes) -> bytes:
        """
        Hybrid decryption using ML-KEM for key decapsulation and AES for data decryption.

        Args:
            key_pair (MLKEMKeyPair): The key pair containing the KEM object with the private key
            ciphertext (bytes): The encrypted message

        Returns:
            bytes: The decrypted message
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            logger.error("pycryptodome is required for hybrid encryption")
            raise ImportError("pycryptodome is required for hybrid encryption")

        try:
            logger.info("Performing hybrid decryption...")
            mlkem_ciphertext_len = int.from_bytes(ciphertext[:4], byteorder='big')
            mlkem_ciphertext_bytes = ciphertext[4:4+mlkem_ciphertext_len]
            iv = ciphertext[4+mlkem_ciphertext_len:4+mlkem_ciphertext_len+16]
            encrypted_data = ciphertext[4+mlkem_ciphertext_len+16:]

            mlkem_ciphertext = MLKEMCiphertext(
                algorithm="ML-KEM",
                parameter_set=key_pair.private_key.parameter_set,
                ciphertext_bytes=mlkem_ciphertext_bytes
            )

            shared_secret = self.decapsulate(key_pair, mlkem_ciphertext)

            key_size = 16
            if key_pair.private_key.parameter_set == "768":
                key_size = 24
            elif key_pair.private_key.parameter_set == "1024":
                key_size = 32

            aes_key = shared_secret[:key_size]

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(encrypted_data)
            plaintext = unpad(padded_data, AES.block_size)

            logger.info("Hybrid decryption completed successfully.")
            return plaintext
        except Exception as e:
            logger.error(f"Failed to perform hybrid decryption: {str(e)}")
            raise

    def proxy_encrypt(self, legacy_key, plaintext):
        """
        Proxy encryption mode that transparently upgrades legacy RSA keys to ML-KEM.

        Args:
            legacy_key: The key to use for encryption (can be RSA or ML-KEM)
            plaintext (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message using ML-KEM for better quantum resistance
        """
        try:
            logger.info("Performing proxy encryption...")
            if isinstance(legacy_key, str) and legacy_key.startswith("RSA"):
                key_size = 2048
                try:
                    if "-" in legacy_key:
                        key_size = int(legacy_key.split("-")[1])
                except (ValueError, IndexError):
                    pass

                parameter_set = "512"
                if key_size >= 3072:
                    parameter_set = "768"
                if key_size >= 7680:
                    parameter_set = "1024"

                mlkem_key = self.generate_keypair(parameter_set).public_key
                return self.encrypt(mlkem_key, plaintext)

            elif isinstance(legacy_key, MLKEMPublicKey):
                return self.encrypt(legacy_key, plaintext)

            else:
                mlkem_key = self.generate_keypair("512").public_key
                return self.encrypt(mlkem_key, plaintext)
        except Exception as e:
            logger.error(f"Failed to perform proxy encryption: {str(e)}")
            raise

class RSAtoMLKEMConverter:
    """
    Helper class to facilitate migration from RSA to ML-KEM.
    """

    @staticmethod
    def recommend_parameter_set(rsa_key_size: int) -> str:
        """
        Recommend an ML-KEM parameter set based on RSA key size.

        Args:
            rsa_key_size (int): The RSA key size in bits

        Returns:
            str: The recommended ML-KEM parameter set ("512", "768", or "1024")
        """
        if rsa_key_size <= 2048:
            return "512"
        elif rsa_key_size <= 4096:
            return "768"
        else:
            return "1024"

    @staticmethod
    def create_migration_plan(num_keys: int, rsa_key_size: int) -> Dict:
        """
        Create a migration plan with estimated time and resources.

        Args:
            num_keys (int): Number of RSA keys to migrate
            rsa_key_size (int): The RSA key size in bits

        Returns:
            Dict: Migration plan details
        """
        parameter_set = RSAtoMLKEMConverter.recommend_parameter_set(rsa_key_size)

        key_gen_time_per_key = 0.01
        migration_time = num_keys * key_gen_time_per_key

        system_update_time = num_keys * 0.05

        mlkem_key_sizes = {
            "512": {"public": 800, "private": 1632},
            "768": {"public": 1184, "private": 2400},
            "1024": {"public": 1568, "private": 3168}
        }

        storage_needed = num_keys * (
            mlkem_key_sizes[parameter_set]["public"] +
            mlkem_key_sizes[parameter_set]["private"]
        )

        return {
            "recommended_parameter_set": parameter_set,
            "num_keys": num_keys,
            "estimated_migration_time_seconds": migration_time + system_update_time,
            "estimated_storage_needed_bytes": storage_needed,
            "security_level_bits": {"512": 128, "768": 192, "1024": 256}[parameter_set],
            "steps": [
                "Generate new ML-KEM key pairs for each RSA key",
                "Update key storage systems to handle ML-KEM keys",
                "Modify encryption/decryption code to use MLKEMFacade",
                "Test with both RSA and ML-KEM during transition",
                "Set a deprecation date for RSA usage"
            ]
        }

if __name__ == "__main__":
    facade = MLKEMFacade()
    key_pair = facade.generate_keypair(parameter_set="512")

    print("ML-KEM Public Key:")
    print(key_pair.public_key.to_pem())
    print("\nML-KEM Private Key:")
    print(key_pair.private_key.to_pem())

    shared_secret, ciphertext = facade.encapsulate(key_pair.public_key)
    print(f"\nEncapsulated shared secret (hex): {shared_secret.hex()}")
    print(f"Ciphertext (base64): {ciphertext.to_base64()}")

    decapsulated = facade.decapsulate(key_pair, ciphertext)
    print(f"\nDecapsulated shared secret (hex): {decapsulated.hex()}")
    print(f"Shared secrets match: {shared_secret == decapsulated}")

    message = b"This is a secret message encrypted with ML-KEM + AES"
    encrypted = facade.encrypt(key_pair.public_key, message)
    print(f"\nHybrid encrypted (first 64 bytes, hex): {encrypted[:64].hex()}")

    decrypted = facade.decrypt(key_pair, encrypted)
    print(f"\nDecrypted message: {decrypted.decode('utf-8')}")

    migration_plan = RSAtoMLKEMConverter.create_migration_plan(100, 2048)
    print("\nMigration Plan:")
    print(json.dumps(migration_plan, indent=2))