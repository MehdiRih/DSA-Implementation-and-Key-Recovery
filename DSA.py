from Crypto.Util import number
from hashlib import sha1
import random

def generate_prime_numbers(bit_length_p=1024, bit_length_q=160):
    """Generate a 1024-bit prime p and a 160-bit prime q."""
    q = number.getPrime(bit_length_q)
    while True:
        k = number.getRandomNBitInteger(bit_length_p - bit_length_q)
        p = k * q + 1
        if number.isPrime(p):
            break
    return p, q

def find_generator(p, q):
    """Find a generator g of the order-q subgroup of Zp*."""
    while True:
        h = number.getRandomRange(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g != 1:
            return g

def generate_keys(q, g, p):
    """Generate the signature key pair (x, y)."""
    x = random.randint(1, q - 1)  # Private key
    y = pow(g, x, p)  # Public key
    return x, y

def sign_message(m, q, g, p, x, k=None):
    """Sign the message using the private key x."""
    if k is None:
        k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    k_inv = pow(k, q-2, q)  # Fermat's little theorem for multiplicative inverse
    m_hash = sha1(str(m).encode()).hexdigest()
    s = (k_inv * (int(m_hash, 16) + x * r)) % q
    return r, s, k  # Return k as well to verify it's the same for both signatures


def verify_signature(m, r, s, q, g, p, y):
    """Verify the signature using the public key y."""
    m_hash = sha1(str(m).encode()).hexdigest()
    w = pow(s, q-2, q)  # Modular inverse of s
    u1 = (int(m_hash, 16) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# Main execution flow
p, q = generate_prime_numbers()
g = find_generator(p, q)
x, y = generate_keys(q, g, p)
m = 582346829557612  # Example message
r, s, _ = sign_message(m, q, g, p, x)
print("Signature:", (r, s))
is_valid = verify_signature(m, r, s, q, g, p, y)
print("Signature valid:", is_valid)
