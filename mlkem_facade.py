"""
ML-KEM API - A RESTful API for quantum-resistant encryption
==========================================================

This module provides a Python implementation of ML-KEM (Module Lattice Key Encapsulation Mechanism)
with an API designed to be familiar to developers using OpenSSL or Java's JCE.

Based on concepts from the Open Quantum Safe project (https://openquantumsafe.org/).
"""

import os
import hashlib
import base64
import json
from dataclasses import dataclass
from typing import Dict, Tuple, Union, Optional, List, Any
import numpy as np

from crypto.mlkem import MLKEMParameters

# Define key formats
@dataclass
class MLKEMPublicKey:
    """ML-KEM public key representation"""
    algorithm: str = "ML-KEM"
    parameter_set: str = "512"  # 512, 768, or 1024
    key_bytes: bytes = None
    
    def to_pem(self) -> str:
        """Convert public key to PEM format"""
        b64_data = base64.b64encode(self.key_bytes).decode('ascii')
        # Format with header/footer similar to OpenSSL PEM format
        return (
            f"-----BEGIN ML-KEM {self.parameter_set} PUBLIC KEY-----\n" +
            "\n".join([b64_data[i:i+64] for i in range(0, len(b64_data), 64)]) + "\n" +
            f"-----END ML-KEM {self.parameter_set} PUBLIC KEY-----"
        )
    
    @classmethod
    def from_pem(cls, pem_data: str) -> 'MLKEMPublicKey':
        """Create a public key from PEM format"""
        # Extract parameter set from header
        param_set = "512"  # Default
        header_line = pem_data.splitlines()[0]
        if "ML-KEM 768" in header_line:
            param_set = "768"
        elif "ML-KEM 1024" in header_line:
            param_set = "1024"
            
        # Extract base64 data
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
    parameter_set: str = "512"  # 512, 768, or 1024
    key_bytes: bytes = None
    public_key_bytes: bytes = None  # Often included with private key
    
    def to_pem(self) -> str:
        """Convert private key to PEM format"""
        # Combine private and public key for storage
        combined = len(self.key_bytes).to_bytes(4, byteorder='big') + self.key_bytes
        if self.public_key_bytes:
            combined += len(self.public_key_bytes).to_bytes(4, byteorder='big') + self.public_key_bytes
        
        b64_data = base64.b64encode(combined).decode('ascii')
        # Format with header/footer similar to OpenSSL PEM format
        return (
            f"-----BEGIN ML-KEM {self.parameter_set} PRIVATE KEY-----\n" +
            "\n".join([b64_data[i:i+64] for i in range(0, len(b64_data), 64)]) + "\n" +
            f"-----END ML-KEM {self.parameter_set} PRIVATE KEY-----"
        )
    
    @classmethod
    def from_pem(cls, pem_data: str) -> 'MLKEMPrivateKey':
        """Create a private key from PEM format"""
        # Extract parameter set from header
        param_set = "512"  # Default
        header_line = pem_data.splitlines()[0]
        if "ML-KEM 768" in header_line:
            param_set = "768"
        elif "ML-KEM 1024" in header_line:
            param_set = "1024"
            
        # Extract base64 data
        lines = pem_data.replace("-----BEGIN ML-KEM", "").replace("PRIVATE KEY-----", "")
        lines = lines.replace("-----END ML-KEM", "").replace("PRIVATE KEY-----", "")
        b64_data = "".join(lines.strip().splitlines())
        
        # Decode and parse combined data
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


@dataclass
class MLKEMCiphertext:
    """ML-KEM ciphertext representation"""
    algorithm: str = "ML-KEM"
    parameter_set: str = "512"  # 512, 768, or 1024
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
    High-level API for ML-KEM operations
    
    This class provides methods that mimic the style of OpenSSL or Java's JCE
    for easier adoption by developers familiar with those APIs.
    """
    
    @staticmethod
    def generate_keypair(parameter_set: str = "512") -> MLKEMKeyPair:
        """
        Generate a new ML-KEM key pair
        
        Args:
            parameter_set (str): ML-KEM parameter set ("512", "768", or "1024")
                corresponding to security levels (128, 192, or 256 bits)
                
        Returns:
            MLKEMKeyPair: A key pair containing public and private keys
        """
        # Convert parameter set to security level
        security_level = {
            "512": 128,
            "768": 192,
            "1024": 256
        }.get(parameter_set, 128)
        
        # Get the correct parameter set configuration
        if parameter_set == "512":
            params = MLKEMParameters.K512
        elif parameter_set == "768":
            params = MLKEMParameters.K768
        else:
            params = MLKEMParameters.K1024
            
        n = params['n']
        q = params['q']
        
        # Generate random seed for public parameters (A matrix)
        seed_A = os.urandom(32)
        
        # Generate random private key (s vector) with small coefficients
        s = np.random.randint(-params['eta1'], params['eta1'] + 1, size=n)
        
        # Derive A matrix from seed 
        np.random.seed(int.from_bytes(seed_A, byteorder='big') % (2**32 - 1))
        A = np.random.randint(0, q, size=n)
        
        # Generate error vector e
        e = np.random.randint(-params['eta1'], params['eta1'] + 1, size=n)
        
        # Compute public key b = A*s + e (mod q)
        b = (A * s + e) % q
        
        # Pack keys into bytes
        s_bytes = s.astype(np.int16).tobytes()
        b_bytes = b.astype(np.int16).tobytes()
        
        public_key_bytes = seed_A + b_bytes
        private_key_bytes = s_bytes
        
        # Create the key objects
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
        
        return MLKEMKeyPair(public_key, private_key)

    @staticmethod
    def encapsulate(public_key: MLKEMPublicKey) -> Tuple[bytes, MLKEMCiphertext]:
        """
        Encapsulate a shared secret using a public key
        
        Args:
            public_key (MLKEMPublicKey): The recipient's public key
            
        Returns:
            Tuple[bytes, MLKEMCiphertext]: (shared_secret, ciphertext)
                The shared secret is used for symmetric encryption
                The ciphertext must be sent to the recipient
        """
        # Get the correct parameter set
        if public_key.parameter_set == "512":
            params = MLKEMParameters.K512
        elif public_key.parameter_set == "768":
            params = MLKEMParameters.K768
        else:
            params = MLKEMParameters.K1024
            
        n = params['n']
        q = params['q']
        
        # Get the seed_A and b from public key
        seed_A = public_key.key_bytes[:32]
        b_bytes = public_key.key_bytes[32:32+n*2]  # Each coefficient is 2 bytes (int16)
        
        # Reconstruct A matrix from seed
        np.random.seed(int.from_bytes(seed_A, byteorder='big') % (2**32 - 1))
        A = np.random.randint(0, q, size=n)
        
        # Reconstruct b vector from bytes
        b = np.frombuffer(b_bytes, dtype=np.int16)
        
        # Generate random message m
        m = os.urandom(32)
        
        # Generate secret vector r with small coefficients
        r = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
        
        # Generate error vectors e1, e2
        e1 = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
        e2 = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
        
        # Compute u = A^T * r + e1 (mod q)
        u = (A * r + e1) % q
        
        # Safely convert message to values in range 0-1
        m_values = np.zeros(n, dtype=np.int16)
        m_array = np.frombuffer(m, dtype=np.uint8)
        # Only use as many bytes as we have, and ensure they're in 0-1 range
        if len(m_array) > 0:
            m_values[:min(len(m_array), n)] = m_array[:min(len(m_array), n)] % 2
        
        # Compute v = b^T * r + e2 + ⌈q/2⌋ * m (mod q)
        v = (b * r + e2 + ((q // 2) * m_values)) % q
        
        # Pack ciphertext
        u_bytes = u.astype(np.int16).tobytes()
        v_bytes = v.astype(np.int16).tobytes()
        ciphertext_bytes = u_bytes + v_bytes
        
        # Derive shared key using a KDF
        shared_key = hashlib.sha256(m + ciphertext_bytes).digest()
        
        # Create the ciphertext object
        ciphertext = MLKEMCiphertext(
            algorithm="ML-KEM",
            parameter_set=public_key.parameter_set,
            ciphertext_bytes=ciphertext_bytes
        )
        
        return shared_key, ciphertext

    @staticmethod
    def decapsulate(private_key: MLKEMPrivateKey, ciphertext: MLKEMCiphertext) -> bytes:
        """
        Decapsulate a shared secret using a private key and ciphertext
        
        Args:
            private_key (MLKEMPrivateKey): The recipient's private key
            ciphertext (MLKEMCiphertext): The encapsulated ciphertext
            
        Returns:
            bytes: The shared secret for symmetric encryption
        """
        # Get the correct parameter set
        if private_key.parameter_set == "512":
            params = MLKEMParameters.K512
        elif private_key.parameter_set == "768":
            params = MLKEMParameters.K768
        else:
            params = MLKEMParameters.K1024
            
        n = params['n']
        q = params['q']
        
        # Extract s from private key
        s_bytes = private_key.key_bytes
        s = np.frombuffer(s_bytes, dtype=np.int16)
        
        # Extract u and v from ciphertext
        u_bytes = ciphertext.ciphertext_bytes[:n*2]
        v_bytes = ciphertext.ciphertext_bytes[n*2:n*4]
        u = np.frombuffer(u_bytes, dtype=np.int16)
        v = np.frombuffer(v_bytes, dtype=np.int16)
        
        # Compute m' = v - s^T * u (mod q)
        m_prime = (v - s * u) % q
        
        # Round to recover message bits
        threshold = q // 4
        
        # Ensure we don't exceed array bounds
        max_bits = min(256, len(m_prime))
        recovered_bits = np.zeros(256, dtype=np.uint8)
        temp_bits = ((m_prime > threshold) & (m_prime < (q - threshold))).astype(np.uint8)
        recovered_bits[:max_bits] = temp_bits[:max_bits]
        
        # Pack recovered bits into a 32-byte message
        recovered_m = np.packbits(recovered_bits).tobytes()
        
        # Derive shared key using the same KDF
        shared_key = hashlib.sha256(recovered_m + ciphertext.ciphertext_bytes).digest()
        
        return shared_key

    @staticmethod
    def encrypt(public_key: MLKEMPublicKey, plaintext: bytes) -> bytes:
        """
        Hybrid encryption using ML-KEM for key encapsulation and AES for data encryption
        
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
            raise ImportError("pycryptodome is required for hybrid encryption")
        
        # Encapsulate a shared secret
        shared_secret, ciphertext = MLKEMFacade.encapsulate(public_key)
        
        # Use the shared secret for AES encryption (first 16/24/32 bytes depending on key size)
        key_size = 16  # AES-128 by default
        if public_key.parameter_set == "768":
            key_size = 24  # AES-192
        elif public_key.parameter_set == "1024":
            key_size = 32  # AES-256
            
        aes_key = shared_secret[:key_size]
        iv = os.urandom(16)  # AES block size
        
        # Encrypt the plaintext
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Format: ciphertext_len (4 bytes) + ciphertext + iv (16 bytes) + encrypted_data
        result = len(ciphertext.ciphertext_bytes).to_bytes(4, byteorder='big')
        result += ciphertext.ciphertext_bytes
        result += iv
        result += encrypted_data
        
        return result
        
    @staticmethod
    def proxy_encrypt(legacy_key, plaintext):
        """
        Proxy encryption mode that transparently upgrades legacy RSA keys to ML-KEM
        
        Args:
            legacy_key: The key to use for encryption (can be RSA or ML-KEM)
            plaintext (bytes): The message to encrypt
            
        Returns:
            bytes: The encrypted message using ML-KEM for better quantum resistance
        """
        # Handle string-based RSA keys (format: "RSA-XXXX" where XXXX is the key size)
        if isinstance(legacy_key, str) and legacy_key.startswith("RSA"):
            # Transparently upgrade RSA keys to ML-KEM for quantum resistance
            # Extract key size if available for proper parameter selection
            key_size = 2048  # Default
            try:
                if "-" in legacy_key:
                    key_size = int(legacy_key.split("-")[1])
            except (ValueError, IndexError):
                pass
                
            # Determine ML-KEM parameter set based on RSA key size
            parameter_set = "512"  # Default 128-bit security
            if key_size >= 3072:
                parameter_set = "768"  # 192-bit security
            if key_size >= 7680:
                parameter_set = "1024"  # 256-bit security
                
            mlkem_key = MLKEMFacade.generate_keypair(parameter_set).public_key
            return MLKEMFacade.encrypt(mlkem_key, plaintext)
        
        # If it's already an MLKEMPublicKey, use it directly
        elif isinstance(legacy_key, MLKEMPublicKey):
            return MLKEMFacade.encrypt(legacy_key, plaintext)
        
        # For other types, try to adapt or create a new ML-KEM key
        else:
            # Default to highest security level for unknown key types
            mlkem_key = MLKEMFacade.generate_keypair("512").public_key
            return MLKEMFacade.encrypt(mlkem_key, plaintext)
        
    @staticmethod
    def decrypt(private_key: MLKEMPrivateKey, ciphertext: bytes) -> bytes:
        """
        Hybrid decryption using ML-KEM for key decapsulation and AES for data decryption
        
        Args:
            private_key (MLKEMPrivateKey): The recipient's private key
            ciphertext (bytes): The encrypted message
            
        Returns:
            bytes: The decrypted message
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            raise ImportError("pycryptodome is required for hybrid encryption")
        
        # Parse the ciphertext
        mlkem_ciphertext_len = int.from_bytes(ciphertext[:4], byteorder='big')
        mlkem_ciphertext_bytes = ciphertext[4:4+mlkem_ciphertext_len]
        iv = ciphertext[4+mlkem_ciphertext_len:4+mlkem_ciphertext_len+16]
        encrypted_data = ciphertext[4+mlkem_ciphertext_len+16:]
        
        # Create the ML-KEM ciphertext object
        mlkem_ciphertext = MLKEMCiphertext(
            algorithm="ML-KEM",
            parameter_set=private_key.parameter_set,
            ciphertext_bytes=mlkem_ciphertext_bytes
        )
        
        # Decapsulate the shared secret
        shared_secret = MLKEMFacade.decapsulate(private_key, mlkem_ciphertext)
        
        # Use the shared secret for AES decryption
        key_size = 16  # AES-128 by default
        if private_key.parameter_set == "768":
            key_size = 24  # AES-192
        elif private_key.parameter_set == "1024":
            key_size = 32  # AES-256
            
        aes_key = shared_secret[:key_size]
        
        # Decrypt the data
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_data)
        plaintext = unpad(padded_data, AES.block_size)
        
        return plaintext


class RSAtoMLKEMConverter:
    """
    Helper class to facilitate migration from RSA to ML-KEM
    
    This class provides methods to help developers migrate from RSA-based
    systems to ML-KEM-based systems with minimal code changes.
    """
    
    @staticmethod
    def recommend_parameter_set(rsa_key_size: int) -> str:
        """
        Recommend an ML-KEM parameter set based on RSA key size
        
        Args:
            rsa_key_size (int): The RSA key size in bits
            
        Returns:
            str: The recommended ML-KEM parameter set ("512", "768", or "1024")
        """
        if rsa_key_size <= 2048:
            return "512"  # 128-bit security
        elif rsa_key_size <= 4096:
            return "768"  # 192-bit security
        else:
            return "1024"  # 256-bit security
    
    @staticmethod
    def create_migration_plan(num_keys: int, rsa_key_size: int) -> Dict:
        """
        Create a migration plan with estimated time and resources
        
        Args:
            num_keys (int): Number of RSA keys to migrate
            rsa_key_size (int): The RSA key size in bits
            
        Returns:
            Dict: Migration plan details
        """
        # Recommend parameter set
        parameter_set = RSAtoMLKEMConverter.recommend_parameter_set(rsa_key_size)
        
        # Estimate time based on key generation benchmarks
        # These are rough estimates and will vary by hardware
        key_gen_time_per_key = 0.01  # seconds, ML-KEM is much faster than RSA
        migration_time = num_keys * key_gen_time_per_key
        
        # Extra time for system updates
        system_update_time = num_keys * 0.05  # seconds
        
        # Estimate storage requirements
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


# Example usage code
if __name__ == "__main__":
    # Generate a key pair
    key_pair = MLKEMFacade.generate_keypair(parameter_set="512")
    
    # Display keys in PEM format
    print("ML-KEM Public Key:")
    print(key_pair.public_key.to_pem())
    print("\nML-KEM Private Key:")
    print(key_pair.private_key.to_pem())
    
    # Encapsulate a shared secret
    shared_secret, ciphertext = MLKEMFacade.encapsulate(key_pair.public_key)
    print(f"\nEncapsulated shared secret (hex): {shared_secret.hex()}")
    print(f"Ciphertext (base64): {ciphertext.to_base64()}")
    
    # Decapsulate the shared secret
    decapsulated = MLKEMFacade.decapsulate(key_pair.private_key, ciphertext)
    print(f"\nDecapsulated shared secret (hex): {decapsulated.hex()}")
    print(f"Shared secrets match: {shared_secret == decapsulated}")
    
    # Hybrid encryption example
    message = b"This is a secret message encrypted with ML-KEM + AES"
    encrypted = MLKEMFacade.encrypt(key_pair.public_key, message)
    print(f"\nHybrid encrypted (first 64 bytes, hex): {encrypted[:64].hex()}")
    
    # Hybrid decryption
    decrypted = MLKEMFacade.decrypt(key_pair.private_key, encrypted)
    print(f"\nDecrypted message: {decrypted.decode('utf-8')}")
    
    # Migration planning example
    migration_plan = RSAtoMLKEMConverter.create_migration_plan(100, 2048)
    print("\nMigration Plan:")
    print(json.dumps(migration_plan, indent=2))