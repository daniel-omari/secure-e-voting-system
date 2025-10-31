# --- START OF FILE registrar.py ---

# Step 1: Import helper functions and functions from cryptography.io for cryptographic operations.
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Constants for file names and directories
PUBLIC_KEYS_DB_FILE = "public_keys.json"
PRIVATE_KEYS_DIR = "private_keys"

# Ensure the private keys directory exists
if not os.path.exists(PRIVATE_KEYS_DIR):
    os.makedirs(PRIVATE_KEYS_DIR)

# Step 2: Generate an ECDSA key pair for a given voter ID.
#   The private key is saved locally; the public key is returned for inclusion in the public database.
#   Generate a new ECDSA private key using the SECP256R1 curve
#   Serialize and save the private key to a PEM file (no encryption)
#   Serialize the public key to a PEM string (used by the server for signature verification)
def generate_key_pair(voter_id_prefix): # Corrected parameter name
    # Generate a new ECDSA private key using the SECP256R1 curve
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )

    # Serialize and save the private key to a PEM file (no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_filename = os.path.join(PRIVATE_KEYS_DIR, f"{voter_id_prefix}_private.pem")
    with open(private_key_filename, "wb") as f:
        f.write(private_pem)
    print(f"Private key for voter {voter_id_prefix} saved to {private_key_filename}")

    # Serialize the public key to a PEM string (used by the server for signature verification)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8') # Decode to string for JSON storage

    return public_pem


# Step 3: Define a function main that prompts the user for number of voters and generates key pairs for each.
#   Ask the user how many voters to register
#   Load existing public key database if it exists, or start a new one
#   Generate key pairs for each voter and update the public key database
#   Save the updated public key database to disk
def main():
    print("Welcome to the Registrar Key Generation Tool!")

    # Ask the user how many voters to register
    num_voters_str = input("How many voters do you want to register? ")
    try:
        num_voters = int(num_voters_str)
        if num_voters <= 0:
            print("Please enter a positive number of voters.")
            return
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    # Load existing public key database if it exists, or start a new one
    public_keys_db = {}
    if os.path.exists(PUBLIC_KEYS_DB_FILE):
        with open(PUBLIC_KEYS_DB_FILE, "r") as f:
            try:
                public_keys_db = json.load(f)
                print(f"Loaded existing public key database from {PUBLIC_KEYS_DB_FILE}")
            except json.JSONDecodeError:
                print(f"Warning: {PUBLIC_KEYS_DB_FILE} is corrupted or empty. Starting new database.")
                public_keys_db = {}
    else:
        print("No existing public key database found. Creating a new one.")

    # Generate key pairs for each voter and update the public key database
    for i in range(num_voters):
        voter_id_prefix = f"voter_{i+1}" # Simple voter ID scheme
        if voter_id_prefix in public_keys_db:
            print(f"Voter ID {voter_id_prefix} already exists. Overwriting its key pair.")

        public_pem = generate_key_pair(voter_id_prefix)
        public_keys_db[voter_id_prefix] = public_pem
        # The print statement is already inside generate_key_pair

    # Save the updated public key database to disk
    with open(PUBLIC_KEYS_DB_FILE, "w") as f:
        json.dump(public_keys_db, f, indent=4)
    print(f"Updated public key database saved to {PUBLIC_KEYS_DB_FILE}")
    print("Registration complete.")

if __name__ == '__main__':
    main()

# --- END OF FILE registrar.py ---