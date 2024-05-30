#RSA asymmetric cryptography algorithm
"""
The RSA algorithm involves four main stages:
1. Key generation: To generate a private key (to keep) and a public key (to share).
2. Key distribution: Flood the network with the public key.
3. Encryption: The sender encrypts the message using the receivers public key.
4. Decryption: The message is decrypted by the receiver using its private key.

In the code we will only implement three steps
1. Key generation: Generates the public key (e, n) and the private key (d, n).
2. Encryption: Encrypts a plaintext message using the public key.
3. Decryption: Decrypts the ciphertext using the private key.
"""
import random
from sympy import isprime, mod_inverse

# Step 1: Key Generation
"""
 Key Generation:
    1. Select two distinct prime numbers p and q.
    2. Compute n = pq.
    3. Compute the totient function φ(n) = (p-1)(q-1).
    4. Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.
    5. Compute d, the modular multiplicative inverse of e modulo φ(n).
    6. Public key is (e, n) and private key is (d, n).
"""
def generate_keypair(p, q):
    if not (isprime(p) and isprime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal")
    
    # Step 1: select two distinct prime numbers p and q. Then compute n = pq
    n = p * q
    print(f"Step 1 of Key Generation: n = p * q = {p} * {q} = {n}")


    # Step 2: compute the totient function phi(n) = (p-1)(q-1).
    # Phi is the totient of n
    phi = (p-1) * (q-1)
    print(f"Step 2 of Key Generation to Compute the totient function: phi(n) = (p-1) * (q-1) = ({p}-1) * ({q}-1) = {phi}")

    # Step 3: choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    # so, e and phi(n) are coprime
    e = random.randrange(1, phi)
    # use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    print(f"Step 3 of Key Generation: e = {e} (1 < e < {phi} and gcd(e, phi(n)) = 1)")

    # Step 4: Compute d = e^(-1) mod φ(n)
    # we use Extended Euclid's Algorithm to generate the private key
    d = mod_inverse(e, phi)
    print(f"Step 4 of Key Generation: d = e^(-1) mod phi(n) = {d}")
    
    # this will return public and private keypair
    # so public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

#GCD function using modular arithmetic 
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Step 2: Encryption
"""
    Encryption:
    1. Convert each letter in the plaintext to numbers based on the character's ASCII value.
    2. For each number M in the plaintex, compute the ciphertext C as: C = M^e mod n.
"""

def encrypt(pk, plaintext):
    """
    Encryption:
    1. Convert each letter in the plaintext to numbers based on the character's ASCII value.
    2. Compute the ciphertext C for each number M in the plaintext as C = M^e mod n.
    """
    key, n = pk
    cipher = []
    print("\nEncryption Process:\n")
    for char in plaintext:
        m = ord(char)
        c = (m ** key) % n
        cipher.append(c)
        print(f"  {char} -> {m} -> ({m}^{key} mod {n}) = {c}\n")
    return cipher

# Step 3: Decryption
"""
    Decryption:
    1. Compute the plaintext M for each number C in the ciphertext as M = C^d mod n.
    2. Convert each number in the plaintext back to characters.
"""
def decrypt(pk, ciphertext):
    key, n = pk
    plain = []
    print("\nDecryption Process:\n")
    for char in ciphertext:
        m = (char ** key) % n
        plain.append(chr(m))
        print(f"  {char} -> ({char}^{key} mod {n}) = {m} -> {chr(m)}\n")
    return ''.join(plain)

def main():
    print(f"\nRSA (Rivest-Shamir-Adleman) - Asymmetric Algorithm: \n")

    print("\nDone by: \n Sadeel Muwahed 20200232 \n Hussam Jabban 20200920\n")
    print("\nThank you Doctor Mustafa for all your support and the amazing lectures!")

    p = int(input("\nEnter a prime number (p): "))
    q = int(input("\nEnter another prime number (q): "))

     # Ensure n is large enough for ASCII values
    while p * q <= 255:
        print("The product of p and q must be greater than 255 for the encryption to work properly with ASCII values.")
        p = int(input("Enter a prime number (p): "))
        q = int(input("Enter another prime number (q): "))

    print("\nGenerating keys...")
    public, private = generate_keypair(p, q)
    print(f"\nPublic key: {public}")
    print(f"Private key: {private}\n")

    message = input("Enter a message to encrypt: ")
    encrypted_msg = encrypt(public, message)
    print(f"\nEncrypted message: {encrypted_msg}")

    decrypted_msg = decrypt(private, encrypted_msg)
    print(f"\nDecrypted message: {decrypted_msg}")
    



if __name__ == "__main__":
    main()
