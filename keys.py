#Kris Sathwara(euid: ks1290)
#keys.py 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import base64

# Store keys in memory
keys = {}

def generate_key_pair(kid, days_valid=30):
    """Generates a new RSA key pair and stores it with key id (kid) and expiry."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Convert private key to PEM format for JWT encoding
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Set expiry based on days_valid
    expiry = datetime.utcnow() + timedelta(days=days_valid)
    
    # Store all key information
    keys[kid] = {
        "private_key": private_pem,  # Store as PEM bytes
        "public_key": public_key,
        "expiry": expiry,
        "kid": kid
    }

def get_active_keys():
    """Returns active keys (i.e., non-expired) in JWKS format."""
    active_keys = []
    for kid, key_info in keys.items():
        if key_info["expiry"] > datetime.utcnow():
            # Get the public numbers for the key
            public_numbers = key_info["public_key"].public_numbers()
            
            # Create the JWK representation
            active_keys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": int_to_base64(public_numbers.n),
                "e": int_to_base64(public_numbers.e),
            })
    return active_keys

def get_all_keys():
    """Returns all keys (including expired) in JWKS format."""
    all_keys = []
    for kid, key_info in keys.items():
        public_numbers = key_info["public_key"].public_numbers()
        all_keys.append({
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e),
            "exp": int(key_info["expiry"].timestamp())
        })
    return all_keys

def int_to_base64(n):
    """Convert an integer to a base64-encoded string."""
    # Proper padding for URL-safe base64
    bytes_data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    encoded = base64.urlsafe_b64encode(bytes_data).decode('utf-8')
    # Remove padding as per JWK spec
    return encoded.rstrip('=')

def get_key_by_kid(kid):
    """Return the key information associated with a given kid."""
    return keys.get(kid)

# Generate initial keys
generate_key_pair("key1", days_valid=30)
generate_key_pair("expired_key", days_valid=-1)  # Expired key