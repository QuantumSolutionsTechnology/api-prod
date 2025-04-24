import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

def generate_rsa_keys(key_size=2048):
    """
    Generate RSA key pair.
    
    Args:
        key_size (int): Key size in bits (default: 2048)
        
    Returns:
        tuple: (start_time, public_key, private_key, end_time)
    """
    start_time = time.time()
    key = RSA.generate(key_size)
    end_time = time.time()
    
    public_key = key.publickey()
    private_key = key
    
    return start_time, public_key, private_key, end_time

def rsa_encrypt(public_key, plaintext):
    """
    Encrypt a message using RSA.
    
    Args:
        public_key: RSA public key
        plaintext (str): Message to encrypt
        
    Returns:
        bytes: Encrypted message
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    
    # Handle messages longer than the RSA key size
    # For simplicity, we're just encrypting the first chunk that fits
    max_length = public_key.size_in_bytes() - 2 * SHA256.digest_size - 2
    
    if len(plaintext) > max_length:
        plaintext = plaintext[:max_length]
    
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """
    Decrypt a message using RSA.
    
    Args:
        private_key: RSA private key
        ciphertext (bytes): Encrypted message
        
    Returns:
        str: Decrypted message
    """
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def get_rsa_security_level(key_size):
    """
    Get the security level of RSA for a given key size.
    
    Args:
        key_size (int): RSA key size in bits
        
    Returns:
        int: Approximate equivalent security level in bits
    """
    # Based on NIST recommendations (approximate)
    security_levels = {
        1024: 80,   # No longer considered secure
        2048: 112,
        3072: 128,
        4096: 152,
        7680: 192,
        15360: 256
    }
    
    # Find the closest key size
    closest_key_size = min(security_levels.keys(), key=lambda k: abs(k - key_size))
    return security_levels[closest_key_size]
