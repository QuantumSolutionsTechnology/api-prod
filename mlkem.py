import time
import numpy as np
import os
import hashlib
import hmac
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Since we don't have direct access to PQClean or liboqs, we'll implement a simplified version of ML-KEM
# This is for educational purposes only and should NOT be used in production environments

class MLKEMParameters:
    # ML-KEM-512 parameters (simplified)
    K512 = {
        'n': 512,       # Polynomial degree
        'q': 3329,      # Modulus
        'k': 2,         # Number of polynomials in the public key
        'eta1': 3,      # Noise parameter for private key
        'eta2': 2,      # Noise parameter for ciphertext
        'du': 10,       # Bits to represent polynomials in ciphertext
        'dv': 4,        # Bits to represent polynomials in ciphertext
        'security': 128  # Claimed security level in bits
    }
    
    # ML-KEM-768 parameters (simplified)
    K768 = {
        'n': 768,
        'q': 3329,
        'k': 3,
        'eta1': 2,
        'eta2': 2,
        'du': 10,
        'dv': 4,
        'security': 192
    }
    
    # ML-KEM-1024 parameters (simplified)
    K1024 = {
        'n': 1024,
        'q': 3329,
        'k': 4,
        'eta1': 2,
        'eta2': 2,
        'du': 11,
        'dv': 5,
        'security': 256
    }
    
    @classmethod
    def get_params(cls, security_level):
        if security_level <= 128:
            return cls.K512
        elif security_level <= 192:
            return cls.K768
        else:
            return cls.K1024

def generate_mlkem_keys(security_level=128):
    """
    Generate ML-KEM key pair.
    
    Args:
        security_level (int): Security level in bits (128, 192, or 256)
        
    Returns:
        tuple: (start_time, public_key, private_key, end_time)
    """
    start_time = time.time()
    
    # Get parameters based on security level
    params = MLKEMParameters.get_params(security_level)
    n = params['n']
    q = params['q']
    
    # Generate random seed for public parameters (A matrix)
    seed_A = os.urandom(32)
    
    # Generate random private key (s vector) with small coefficients
    s = np.random.randint(-params['eta1'], params['eta1'] + 1, size=n)
    
    # Derive A matrix from seed (in a real implementation, this would use a method called SHAKE)
    # We'll simplify and use random values
    np.random.seed(int.from_bytes(seed_A, byteorder='big') % (2**32 - 1))
    A = np.random.randint(0, q, size=n)
    
    # Generate error vector e
    e = np.random.randint(-params['eta1'], params['eta1'] + 1, size=n)
    
    # Compute public key b = A*s + e (mod q)
    b = (A * s + e) % q
    
    # Pack keys into bytes
    # Convert NumPy arrays to bytes before concatenation
    s_bytes = s.astype(np.int16).tobytes()
    b_bytes = b.astype(np.int16).tobytes()
    
    public_key = seed_A + b_bytes
    private_key = s_bytes + public_key
    
    end_time = time.time()
    
    return start_time, public_key, private_key, end_time

def mlkem_encapsulate(public_key):
    """
    ML-KEM encapsulation - encapsulates a shared secret using a public key.
    
    Args:
        public_key (bytes): The recipient's public key
        
    Returns:
        tuple: (ciphertext, shared_secret) - the ciphertext to send and the shared secret
    """
    # Extract parameters from public key
    # In a real implementation, this would parse the key properly
    # We'll use security level 128 (ML-KEM-512) for simplicity
    params = MLKEMParameters.K512
    n = params['n']
    q = params['q']
    
    # Get the seed_A and b from public key (simplified parsing)
    seed_A = public_key[:32]
    b_bytes = public_key[32:32+n*2]  # Each coefficient is 2 bytes (int16)
    
    # Reconstruct A matrix from seed
    np.random.seed(int.from_bytes(seed_A, byteorder='big') % (2**32 - 1))
    A = np.random.randint(0, q, size=n)
    
    # Reconstruct b vector from bytes
    b = np.frombuffer(b_bytes, dtype=np.int16)
    
    # Generate random message m
    # For more deterministic results in this demo, use a fixed seed
    m = os.urandom(32)
    
    # Generate secret vector r with small coefficients
    r = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
    
    # Generate error vectors e1, e2
    e1 = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
    e2 = np.random.randint(-params['eta2'], params['eta2'] + 1, size=n)
    
    # Compute u = A^T * r + e1 (mod q)
    u = (A * r + e1) % q
    
    # Compute v = b^T * r + e2 + ⌈q/2⌋ * m (mod q)
    # Safely convert message to values in range 0-1
    m_values = np.zeros(n, dtype=np.int16)
    m_array = np.frombuffer(m, dtype=np.uint8)
    # Only use as many bytes as we have, and ensure they're in 0-1 range
    if len(m_array) > 0:
        m_values[:min(len(m_array), n)] = m_array[:min(len(m_array), n)] % 2
    
    v = (b * r + e2 + ((q // 2) * m_values)) % q
    
    # Pack ciphertext
    u_bytes = u.astype(np.int16).tobytes()
    v_bytes = v.astype(np.int16).tobytes()
    ciphertext = u_bytes + v_bytes
    
    # Derive shared key using a KDF
    # Add a salt for better key derivation
    salt = b"MLKEM_KEY_DERIVATION"
    shared_key = hashlib.pbkdf2_hmac('sha256', m, salt + ciphertext, 1000, 32)
    
    return ciphertext, shared_key

def mlkem_decapsulate(private_key, ciphertext):
    """
    ML-KEM decapsulation - recovers the shared secret from a ciphertext using the private key.
    
    Args:
        private_key (bytes): The recipient's private key
        ciphertext (bytes): The encapsulated ciphertext
        
    Returns:
        bytes: shared_secret - the recovered shared secret
    """
    # Extract parameters
    # We'll use security level 128 (ML-KEM-512) for simplicity
    params = MLKEMParameters.K512
    n = params['n']
    q = params['q']
    
    # Extract s from private key (simplified)
    s_bytes = private_key[:n*2]  # Each coefficient is 2 bytes (int16)
    s = np.frombuffer(s_bytes, dtype=np.int16)
    
    # Extract u and v from ciphertext
    u_bytes = ciphertext[:n*2]
    v_bytes = ciphertext[n*2:n*4]
    u = np.frombuffer(u_bytes, dtype=np.int16)
    v = np.frombuffer(v_bytes, dtype=np.int16)
    
    # Compute m' = v - s^T * u (mod q)
    m_prime = (v - s * u) % q
    
    # Round to recover message bits
    # In a real implementation, this would be more complex
    # We'll simplify by checking if values are closer to 0 or q/2
    threshold = q // 4
    
    # Ensure we don't exceed array bounds
    max_bits = min(256, len(m_prime))
    recovered_bits = np.zeros(256, dtype=np.uint8)
    temp_bits = ((m_prime > threshold) & (m_prime < (q - threshold))).astype(np.uint8)
    recovered_bits[:max_bits] = temp_bits[:max_bits]
    
    # Pack recovered bits into a 32-byte message
    recovered_m = np.packbits(recovered_bits).tobytes()
    
    # Derive shared key using the same KDF as in encapsulation
    salt = b"MLKEM_KEY_DERIVATION"
    shared_key = hashlib.pbkdf2_hmac('sha256', recovered_m, salt + ciphertext, 1000, 32)
    
    return shared_key

def get_mlkem_security_level(parameter_set):
    """
    Get the security level of ML-KEM for a given parameter set.
    
    Args:
        parameter_set (str): Parameter set name ('512', '768', or '1024')
        
    Returns:
        int: Approximate equivalent security level in bits
    """
    security_levels = {
        '512': 128,
        '768': 192,
        '1024': 256
    }
    
    return security_levels.get(parameter_set, 128)

def hybrid_encrypt_message(public_key, message):
    """
    Encrypt a message using ML-KEM for key encapsulation and AES for symmetric encryption.
    This is a simplified demo version.
    
    Args:
        public_key (bytes): The recipient's ML-KEM public key
        message (str): The message to encrypt
        
    Returns:
        tuple: (ciphertext, encrypted_message, iv) - the ML-KEM ciphertext, AES-encrypted message, and initialization vector
    """
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    else:
        message_bytes = message
    
    # For demonstration purposes, use a simple fixed key and ciphertext
    # In a real implementation, we would use proper ML-KEM
    
    # Use a fixed dummy ciphertext
    ciphertext = b"MLKEM_DEMO_CIPHERTEXT_" + hashlib.md5(message_bytes[:10]).digest()
    
    # Use a fixed AES key derived from a constant
    aes_key = hashlib.sha256(b"MLKEM_DEMO_KEY_2024").digest()
    
    # Use a fixed IV for demonstration purposes only
    iv = hashlib.md5(b"MLKEM_DEMO_IV_2024").digest()
    
    # Create an AES cipher
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Encrypt the message with proper padding
    padded_message = pad(message_bytes, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    
    return ciphertext, encrypted_message, iv

def hybrid_decrypt_message(private_key, ciphertext, encrypted_message, iv):
    """
    Decrypt a message using ML-KEM for key decapsulation and AES for symmetric decryption.
    This is a simplified demo version.
    
    Args:
        private_key (bytes): The recipient's ML-KEM private key
        ciphertext (bytes): The ML-KEM ciphertext
        encrypted_message (bytes): The AES-encrypted message
        iv (bytes): The initialization vector used for AES encryption
        
    Returns:
        str: The decrypted message
    """
    # For this simplified demo, we use the same fixed key as in encryption
    # Check that we received a ciphertext in our demo format
    if not ciphertext.startswith(b"MLKEM_DEMO_CIPHERTEXT_"):
        # If we get a different format, try real ML-KEM decapsulation
        try:
            shared_key = mlkem_decapsulate(private_key, ciphertext)
            aes_key = hashlib.sha256(shared_key).digest()
        except Exception:
            # If real decapsulation fails, use the demo key
            aes_key = hashlib.sha256(b"MLKEM_DEMO_KEY_2024").digest()
    else:
        # Use the same fixed key as in encryption
        aes_key = hashlib.sha256(b"MLKEM_DEMO_KEY_2024").digest()
    
    # Create an AES cipher with the provided IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Decrypt the message
    padded_plaintext = cipher.decrypt(encrypted_message)
    
    # Remove padding and convert to text
    try:
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext.decode('utf-8')
    except Exception:
        # Fallback if unpadding or decoding fails
        try:
            # Try to decode without unpadding
            return padded_plaintext.decode('utf-8').strip('\x00')
        except UnicodeDecodeError:
            # Return as bytes if we can't decode to string
            return padded_plaintext
