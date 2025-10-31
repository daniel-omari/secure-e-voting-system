# This builds upon the skeleton code file for lab 1. Any instructions that are new have NEW at the beginning of the line.

# Step 1: Import the requests library to send HTTP requests to the server.
# Import libraries for cryptographic operations.
import requests
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64 # For encoding/decoding binary signatures to/from string for JSON

# Step 2: Define the base URL of the server
#   This should match the host and port used in server.py
SERVER_URL = "http://localhost:5000"
PRIVATE_KEYS_DIR = "private_keys" # Directory where registrar saves private keys
# Client-side known allowed candidates for pre-validation (optional but good for UX)
CLIENT_ALLOWED_CANDIDATES = ["Alice", "Bob", "Charlie"]

# Step 3: Write a function that takes as input a voter ID and loads the voter's private key from a PEM file.
#   This key is used to sign the vote before submission.
#   The function should return an error if the voter ID is not an eligible voter.
def load_private_key(voter_id):
    private_key_filename = os.path.join(PRIVATE_KEYS_DIR, f"{voter_id}_private.pem")
    if not os.path.exists(private_key_filename):
        # The function should return an error if the voter ID is not an eligible voter.
        print(f"Error: Private key file for voter ID '{voter_id}' not found at {private_key_filename}. Please ensure the voter is registered.")
        return None
    try:
        with open(private_key_filename, "rb") as f:
            private_pem = f.read()
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None, # Assuming no encryption for private keys
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        print(f"Error loading private key for voter ID '{voter_id}': {e}")
        return None

# Step 4: Write a function to sign the vote.
#   Your function should take as input a private signing key and a candidate, and should return a signature.
#   Convert signature to hex string for transmission
def sign_vote(private_key, voter_id, candidate_name):
    # The message to be signed must be consistent with what the server expects to verify.
    # It includes the voter_id and candidate_name.
    message = f"{voter_id},{candidate_name}"
    message_bytes = message.encode('utf-8')

    # Sign the message using the provided private key and ECDSA with SHA256.
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    # Convert signature to hex string for transmission (or base64, as used previously for JSON compatibility)
    # Base64 is typically better for binary data in JSON. The previous server example used base64,
    # so let's stick to base64 for consistency in transmission via JSON.
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return signature_b64

# NEW Step 5: Write a function to get the status of the server.
#   NEW Your function should return the current status, or an error message if the status cannot be retrieved.
def get_election_status():
    try:
        response = requests.get(f"{SERVER_URL}/status")
        response.raise_for_status()
        status_data = response.json()
        return status_data.get("status")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching status: {e.response.json().get('error', e)}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while fetching status: {e}")
        return None

# Step 6: Write a function to send a vote
#   NEW Your function must first retrieve the status of the election. If the election is not open, or the election status cannot be retrieved, 
#   NEW return an error message
#   Generate a signature using the signing function in step 4.
#   Prepare the headers and JSON payload
#   Include voter ID, candidate name, and signature in the payload.
#   Print the payload for testing purposes.
#   Send a POST request to the /vote endpoint and raise an error if the server responds with a failure code (e.g. 400 or 500)
#   Print the server's response (should be a confirmation message)
def send_vote(voter_id, candidate_name):
    election_status = get_election_status()
    if election_status is None:
        print("Error: Could not retrieve election status. Vote not submitted.")
        return
    if election_status != "OPEN":
        print(f"Error: Election is {election_status}. Cannot submit vote when election is not OPEN.")
        return
    
    # Load the private key for the given voter ID.
    private_key = load_private_key(voter_id)
    if private_key is None:
        return # Error message already printed by load_private_key

    # Validate candidate on client-side for better UX (optional, server will also validate)
    if candidate_name not in CLIENT_ALLOWED_CANDIDATES:
        print(f"Error: Invalid vote option '{candidate_name}'. Allowed candidates are: {', '.join(CLIENT_ALLOWED_CANDIDATES)}")
        return

    # Generate a signature using the signing function in step 4.
    signature = sign_vote(private_key, voter_id, candidate_name)

    headers = {"Content-Type": "application/json"}
    # Include voter ID, candidate name, and signature in the payload.
    payload = {
        "voter_id": voter_id,
        "candidate": candidate_name,
        "signature": signature
    }

    # Print the payload for testing purposes.
    print(f"\n--- Sending Vote Payload ---")
    print(json.dumps(payload, indent=4))
    print(f"----------------------------")

    try:
        response = requests.post(f"{SERVER_URL}/vote", headers=headers, json=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        print(f"Server response: {response.json()}")
    except requests.exceptions.HTTPError as e:
        print(f"Error sending vote: {e.response.json().get('error', e)}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Step 7: Write a function to fetch current vote results
#   First check the election status. Return the result only if the election status is "closed".
#   Return an error message if status cannot be retrieved or status is "open".
#   Send a GET request to the /results endpoint
#   Print the vote tally in a readable format
def get_results():
    election_status = get_election_status()
    if election_status is None:
        print("Error: Could not retrieve election status. Results not fetched.")
        return

    if election_status != "CLOSED":
        print(f"Error: Election is {election_status}. Results can only be retrieved when election is CLOSED.")
        return
    
    try:
        response = requests.get(f"{SERVER_URL}/results")
        response.raise_for_status()
        results = response.json()
        
        if "message" in results and "instructions" in results:
            print("\nElection Results Status:")
            print(f"- {results['message']}")
            print(f"- {results['instructions']}")
            print("\nNote: Only an authorized administrator can reconstruct the final tally.")
        else:
            print("\nUnexpected results format. Server response:")
            print(json.dumps(results, indent=2))
        print("-" * 25)

    except requests.exceptions.HTTPError as e:
        print(f"Error fetching results: {e.response.json().get('error', e)}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure the server is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Step 8: Create a simple command-line interface
#   This lets users type commands to vote or view results
#   The interface should prompt the user for their voter ID before alloing them to vote or view results.
#   The voter ID must match a registered key.
#   If the user types a vote command, extract the candidate name and send the vote
#   If the user types 'results', fetch and display the current tally
#   NEW If the user types 'status', fetch and display the election status.
def main():
    print("Welcome to the Voting Client!")
    print("Please enter your Voter ID to proceed.")

    voter_id = None
    while voter_id is None:
        input_voter_id = input("Enter your Voter ID (e.g., voter_1): ").strip()
        # The voter ID must match a registered key.
        # We'll check if a private key file exists for this ID.
        if os.path.exists(os.path.join(PRIVATE_KEYS_DIR, f"{input_voter_id}_private.pem")):
            voter_id = input_voter_id
            print(f"Logged in as {voter_id}.")
        else:
            print(f"Error: No private key found for '{input_voter_id}'. Please enter a valid registered Voter ID.")
            # For strictness, you could also try to load the key immediately here to verify its integrity.
            # However, `load_private_key` will do this later for the vote command.

    print(f"\nCommands: 'vote <candidate_name>', 'results', 'exit'")
    while True:
        command = input(f"\n{voter_id}> ").strip()
        if command.lower() == "exit":
            print("Exiting client.")
            break

        elif command.lower() == "results":
            get_results()

        elif command.lower() == "status":
            status = get_election_status()
            if status:
                print(f"Current Election Status: {status}")
            else:
                print("Failed to retrieve election status.")

        elif command.lower().startswith("vote "):
            parts = command.split(" ", 1) # Split only once to get the candidate name
            if len(parts) > 1:
                candidate = parts[1].strip()
                send_vote(voter_id, candidate)
            else:
                print("Invalid vote command. Usage: 'vote <candidate_name>'")
        else:
            print("Unknown command. Please use 'vote <candidate_name>', 'results', or 'exit'.")

if __name__ == "__main__":
    main()