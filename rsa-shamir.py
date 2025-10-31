# Step 1: Important any packages, including those from cryptography.io
#   You must also import functions from your solution to task 1.
import random
import sys
import os
from typing import List, Tuple

from shamir import generate_shares, reconstruct, Share, eval_polynomial, lagrange_interpolate_at_zero

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# You may use the following parameters.
RSA_KEY_SIZE = 1024   
N_SHARES = 3
THRESHOLD = 2         

# The following function finds a prime that is greater than or equal to some target value. 
def is_probable_prime(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# This function will test odd numbers to find a prime.
# You can use it to pick a prime for Shamir secrey sharing that is greater than the secret key. 
def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate

# The following functions can be used to convert integers to bytes and bytes to integers respectively. 
def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder="big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

# -------------------------------------------------------------------------------------------
# Here you will write interactive prompt functions that take input from the user.

# Step 2: Write a function 'prompt_message' that asks a user to input a message to encrypt. 
#   Your function should return the message as bytes.
def prompt_message() -> bytes:
    message_str = input("Enter a message to encrypt: ")
    return message_str.encode('utf-8')

# Step 3: Write a function 'prompt_share_ids' that prompts the user to enter the share ids that will be used
# for reconstruction of the secret key. 
#   Your function should take as input a list of available ids and the threshold that is required
#   to reconstruct the secret key. 
#   Your function should prompt the user to input share ids separated by commas (e.g., 1,2).
#   Users must input a number of share ids that is equal to or greater than the threshold.
#   If users do not provide valid share ids, or do not provide enough shares, your function should
#   return an error. 
#   Return the shares to be used for reconstruction.
def prompt_share_ids(available_ids: List[int], threshold: int) -> List[int]:
    while True:
        try:
            ids_input = input(f"Enter {threshold} or more share IDs for reconstruction (e.g., {','.join(map(str, available_ids[:threshold]))}): ")
            chosen_ids_str = [x.strip() for x in ids_input.split(',')]
            
            chosen_ids = []
            for id_str in chosen_ids_str:
                if not id_str.isdigit():
                    raise ValueError(f"Invalid share ID '{id_str}'. IDs must be integers.")
                chosen_ids.append(int(id_str))

            if len(chosen_ids) < threshold:
                print(f"Error: You must provide at least {threshold} share IDs.")
                continue

            # Remove duplicates and sort for consistency
            chosen_ids = sorted(list(set(chosen_ids)))

            # Check if chosen IDs are valid and available
            for chosen_id in chosen_ids:
                if chosen_id not in available_ids:
                    raise ValueError(f"Share ID {chosen_id} is not an available ID. Available IDs are: {available_ids}")

            return chosen_ids
        except ValueError as e:
            print(f"Input Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
# -------------------------------------------------------------------------------------------


# Step 4: Write a function main as follows:
def main():
    print("--- Threshold RSA with Shamir Secret Sharing ---")
#   1. Generate an RSA key pair using cryptography.io. 
#       You should use public exponent 65537 and RSA_KEY_SIZE (defined at beginning of file) for the key size. 
#       You should store the public key in a variable public_key and the private key in a vaiable private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print(f"\n1. RSA Key Pair Generated (Key Size: {RSA_KEY_SIZE} bits)")

#   2. The following code will extract private numbers from the private key.
    priv_nums = private_key.private_numbers()
    p = priv_nums.p
    q = priv_nums.q
    d = priv_nums.d
    e = priv_nums.public_numbers.e
    n = priv_nums.public_numbers.n
#   We will be sharing private key d only. 
#   Print the bit length of the modulus n and private key d.
    print(f"2. Extracted RSA Private Numbers:")
    print(f"   Modulus (n) bit length: {n.bit_length()}")
    print(f"   Private exponent (d) bit length: {d.bit_length()}")

#   3. Choose a Shamir prime P that is greater than d.
#       You should use next_probable_prime_at_least(d + 1)
#       Print the bit length of P.
    shamir_prime_P = next_probable_prime_at_least(d + 1)
    print(f"\n3. Shamir Prime P chosen: {shamir_prime_P}")
    print(f"   Shamir Prime (P) bit length: {shamir_prime_P.bit_length()}")

#   4. Generate N_SHARES (defined at top of file) shares of private key d.
#       You should use generate_shares function from task 1.
#       Use threshold THRESHOLD (defined at top of file) and the Shamir prime P as additional inputs. 
#       Print the share ids and shares
    shares_of_d = generate_shares(d, N_SHARES, THRESHOLD, shamir_prime_P)
    available_share_ids = [share[0] for share in shares_of_d]
    print(f"\n4. Generated {N_SHARES} shares for private exponent 'd' (Threshold: {THRESHOLD}):")
    for share in shares_of_d:
        print(f"   Share ID {share[0]}: {share[1]}")

#   5. Prompt user for message to encrypt. 
    original_message = prompt_message()
    print(f"5. Original Message: {original_message.decode('utf-8')}")

#   6. Encrypt message using the RSA algorithm from the cryptography.io library. 
#       Use OAEP for padding and the SHA256 hash function. 
#       Print the ciphertext in hex format.
    ciphertext = public_key.encrypt(
        original_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"\n6. Encrypted Ciphertext (hex): {ciphertext.hex()}")

#   7. Prompt the user to input shares that should be used to reconstruct the private key. 
#       Build a list of chosen shares that preserves the (id, value) tuples
#       Print the shares to be used for reconstruction. 
    chosen_ids_for_reconstruction = prompt_share_ids(available_share_ids, THRESHOLD)
    chosen_shares = [share for share in shares_of_d if share[0] in chosen_ids_for_reconstruction]
    print(f"\n7. Shares chosen for reconstruction:")
    for share in chosen_shares:
        print(f"   Share ID {share[0]}: {share[1]}")

#   8. Reconstruct private key d. 
#       You should use reconstruct function from task 1. 
#       Name the reconstructed key d_rec. 
    d_rec = reconstruct(chosen_shares, shamir_prime_P)
    print(f"\n8. Reconstructed private exponent d_rec: {d_rec}")
    print(f"   Matches original d? {d_rec == d}")

#   9. The following will rebuild the private key using original p and q plus reconstructed d
    dmp1 = d_rec % (p - 1)
    dmq1 = d_rec % (q - 1)
    iqmp = pow(q, -1, p)

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    public_numbers = RSAPublicNumbers(e=e, n=n)
    private_numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d_rec,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=public_numbers
    )
    priv_rebuilt = private_numbers.private_key()

#   10. Decrypt the ciphertext using priv_rebuilt and compare with original message.
#       Output an error if the decrypted message does not match the original message.
#       Else output a message indicating a successful decryption and print the decrypted message. 
    try:
        decrypted_message = priv_rebuilt.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        if decrypted_message == original_message:
            print("\n10. Decryption successful!")
            print(f"    Decrypted Message: {decrypted_message.decode('utf-8')}")
        else:
            print("\n10. ERROR: Decrypted message does NOT match the original message!")
            print(f"    Original: {original_message.decode('utf-8')}")
            print(f"    Decrypted: {decrypted_message.decode('utf-8')}")
    except Exception as e:
        print(f"\n10. ERROR during decryption: {e}")
        print("    This usually indicates an issue with the reconstructed private key.")


if __name__ == '__main__':
    main()