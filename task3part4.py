from Crypto.Util.number import getPrime, inverse
from hashlib import sha256

# RSA key generation
def generate_keypair(bits):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return ((n, e), (n, d))

# RSA signing: Sign the message with the private key
def sign(m, private_key):
    n, d = private_key
    return pow(m, d, n)

# RSA verification: Verify the signature with the public key
def verify(signature, public_key):
    n, e = public_key
    return pow(signature, e, n)

# Convert string to int
def string_to_int(msg):
    return int.from_bytes(msg.encode(), 'big')

# Convert int to string
def int_to_string(m):
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# Mallory forges a new signature
def signature_forgery(public_key, signature, r, private_key):
    n, d = private_key
    r_d = pow(r, d, n)
    forged_signature = (signature * r_d) % n
    return forged_signature

def main():
    # Key generation for Alice
    public_key, private_key = generate_keypair(2048)

    # Original message from Alice
    msg = "Pay 100 dollars"
    m = string_to_int(msg)

    # Alice signs the message
    signature = sign(m, private_key)
    print(f"Original signature: {signature}")

    # Mallory chooses an arbitrary r
    r = 3  # Can be any random value chosen by Mallory

    # Mallory forges a new signature for a different message
    forged_signature = signature_forgery(public_key, signature, r, private_key)

    # The new message corresponding to the forged signature
    new_message_int = (m * r) % public_key[0]  # m' = m * r mod n
    new_message = int_to_string(new_message_int)
    print(f"Mallory's new message: {new_message}")
    print(f"Forged signature: {forged_signature}")

    # Verify that the forged signature is valid for the new message
    verified_message_int = verify(forged_signature, public_key)
    verified_message = int_to_string(verified_message_int)

    print(f"Verified message from forged signature: {verified_message}")

if __name__ == "__main__":
    main()