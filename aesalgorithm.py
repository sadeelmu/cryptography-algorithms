#AES: symmetric encryption algorithm
"""
The Advanced Encryption Standard (AES) is a symmetric encryption algorithm widely used across the globe to secure data. 
The process involves several mathematical operations and transformations that ensure the data is encrypted in a secure
and non-reversible manner unless the correct decryption key is provided.
"""

"""
Steps of AES Algorithm:

Firstly we do initialization by asking the user for the plaintext that will be encrypted and the key we will use for the 
encryption and decryption process. Both plaintext and key must be given in hexadeimal.
We also must define the S-BOX that will be used for the Byte Substitution.

1. AddRoundKey
2. Byte Substitution
3. ShiftRows
4. Mix Column

Then we do Step 5. AddRoundKey again to repeat rounds 
"""
import numpy as np

# Define the S-box used for the SubBytes step in the encryption process 
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Define the inverse S-box used for the InvSubBytes step in the decryption process 
INV_SBOX = [SBOX.index(x) for x in range(256)]

# polynomial 
"""
The gmul function multiplies two elements a and b in the finite field GF(2^8), using the  polynomial
x^8 + x^4 + x^3 + x + 1 (0x1B)
"""
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

# Step 1 in Encryption, Step 4 in Decryption: 
# AddRoundKey 
def add_round_key(state, round_key):
    return state ^ round_key

# Encryption Process

# Step 2: SubBytes 
def sub_bytes(state):
    return np.vectorize(lambda x: SBOX[x])(state)

# Step 3: MixColumns 
def mix_columns(state):
    mixed = np.zeros_like(state)
    for i in range(4):
        mixed[0, i] = gmul(state[0, i], 2) ^ gmul(state[1, i], 3) ^ state[2, i] ^ state[3, i]
        mixed[1, i] = state[0, i] ^ gmul(state[1, i], 2) ^ gmul(state[2, i], 3) ^ state[3, i]
        mixed[2, i] = state[0, i] ^ state[1, i] ^ gmul(state[2, i], 2) ^ gmul(state[3, i], 3)
        mixed[3, i] = gmul(state[0, i], 3) ^ state[1, i] ^ state[2, i] ^ gmul(state[3, i], 2)
    return mixed

# Step 4: ShiftRows 
def shift_rows(state):
    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    return state

# Decryption Process

# Step 1: InvMixColumns 
def inv_mix_columns(state):
    mixed = np.zeros_like(state)
    for i in range(4):
        mixed[0, i] = gmul(state[0, i], 0x0e) ^ gmul(state[1, i], 0x0b) ^ gmul(state[2, i], 0x0d) ^ gmul(state[3, i], 0x09)
        mixed[1, i] = gmul(state[0, i], 0x09) ^ gmul(state[1, i], 0x0e) ^ gmul(state[2, i], 0x0b) ^ gmul(state[3, i], 0x0d)
        mixed[2, i] = gmul(state[0, i], 0x0d) ^ gmul(state[1, i], 0x09) ^ gmul(state[2, i], 0x0e) ^ gmul(state[3, i], 0x0b)
        mixed[3, i] = gmul(state[0, i], 0x0b) ^ gmul(state[1, i], 0x0d) ^ gmul(state[2, i], 0x09) ^ gmul(state[3, i], 0x0e)
    return mixed

# Step 2: InvShiftRows 
def inv_shift_rows(state):
    state[1] = np.roll(state[1], 1)
    state[2] = np.roll(state[2], 2)
    state[3] = np.roll(state[3], 3)
    return state

# Step 3: InvSubBytes 
def inv_sub_bytes(state):
    return np.vectorize(lambda x: INV_SBOX[x])(state)


def aes_algo():

    print(f"\nAES (Advanced Encryption Standard) - Symmetric Algorithm: \n")

    print("Thank you Doctor Mustafa for all your support and the amazing lectures!\n")
    print("Done by: \nSadeel Muwahed 20200232 \nHussam Jabban 20200920 \n")

    print("\nEnter the plaintext (16 bytes in hexadecimal, for example: 08090A0B0C0D0E0F0001020304050607):")
    plaintext_hex = input().strip()
    print("\nEnter the key (16 bytes in hexadecimal, for example: 10101010101010101010101010101010):")
    key_hex = input().strip()
    
    # Convert plaintext and key from hexadecimal to byte arrays
    plaintext = [int(plaintext_hex[i:i+2], 16) for i in range(0, len(plaintext_hex), 2)]
    key = [int(key_hex[i:i+2], 16) for i in range(0, len(key_hex), 2)]
    
    # Convert plaintext and key to state matrices
    state = np.array(plaintext).reshape(4, 4).T
    round_key = np.array(key).reshape(4, 4).T

    # Print the original 
    print(f"\nOriginal plaintext from user input:\n{state}\n")

    print(f"Encryption Process: \n")

    # AddRoundKey
    state = add_round_key(state, round_key)
    print(f"Output after AddRoundKey is performed:\n{state}\n")

    # SubBytes
    state = sub_bytes(state)
    print(f"Output after SubBytes is performed:\n{state}\n")

    # ShiftRows
    state = shift_rows(state)
    print(f"Output after ShiftRows is performed:\n{state}\n")

    # MixColumns
    state = mix_columns(state)
    print(f"Output after MixColumns is performed:\n{state}\n")

    # Encryption result
    ciphertext = state
    print(f"Ciphertext:\n{ciphertext}\n")

    print(f"Decryption Process: \n")

    # Decryption process00
    state = ciphertext

    # Inverse functions
    state = inv_mix_columns(state)
    print(f"Output after InvMixColumns is performed:\n{state}\n")

    state = inv_shift_rows(state)
    print(f"Output after InvShiftRows is performed:\n{state}\n")

    state = inv_sub_bytes(state)
    print(f"Output after InvSubBytes is performed:\n{state}\n")

    state = add_round_key(state, round_key)
    print(f"Output after AddRoundKey (Decryption) is performed:\n{state}\n")

    # here we ensure that decrypted state matches the original plaintext
    decrypted_plaintext = state.T.flatten().tolist()
    print("Decrypted Plaintext:")
    print([hex(x)[2:].zfill(2) for x in decrypted_plaintext])
    print()



aes_algo()
