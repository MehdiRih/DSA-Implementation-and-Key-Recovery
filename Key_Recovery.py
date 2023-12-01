from hashlib import sha1
from DSA import generate_prime_numbers, find_generator, generate_keys, sign_message
import random

def recover_private_key(r, s, r_new, s_new, m_hash, m_new_hash, q):
    """
    Recover the private key x from two DSA signatures that used the same k.
    
    Parameters:
    r, s (int): Components of the first signature.
    r_new, s_new (int): Components of the second signature.
    m_hash, m_new_hash (int): Hashes of the messages.
    q (int): The prime q used in DSA.
    
    Returns:
    int: The recovered private key x.
    """
    # Ensure r values are the same, as the same k was used
    if r != r_new:
        raise ValueError("r values are not equal. The same k must be used for both signatures.")

    # Calculate the difference in hashes and s values
    hash_diff = m_new_hash - m_hash
    s_diff = s_new - s

    # Calculate the modular inverse of the difference in s values
    s_diff_inv = pow(s_diff, q-2, q)

    # Calculate k
    k = (hash_diff * s_diff_inv) % q

    # Calculate the private key x using the first signature
    r_inv = pow(r, q-2, q)  # Modular inverse of r
    x = ((s * k - m_hash) * r_inv) % q

    return x


p, q = generate_prime_numbers()
g = find_generator(p, q)
x, y = generate_keys(q, g, p)


# Define a constant k for both signatures (to simulate the vulnerability)
k_constant = random.randint(1, q - 1)

# First message and signature
m1 = 582346829557612  # Example message 1
m1_hash = int(sha1(str(m1).encode()).hexdigest(), 16)
r1, s1, k_used_1 = sign_message(m1, q, g, p, x, k=k_constant)

# Second message and signature using the same k
m2 = 8161474912583  # Example message 2
m2_hash = int(sha1(str(m2).encode()).hexdigest(), 16)
r2, s2, k_used_2 = sign_message(m2, q, g, p, x, k=k_constant)

# Verify that the same k was used
assert k_used_1 == k_used_2, "Different k values were used for the signatures."

# ... [rest of your script to verify signatures and perform key recovery] ...

# Simulate key recovery
x_recovered = recover_private_key(r1, s1, r2, s2, m1_hash, m2_hash, q)
print("Recovered private key x:", x_recovered)
