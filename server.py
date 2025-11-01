# Step 1: Import helper functions for handling web requests and JSON responses
#   Import functions from cryptography.io for cryptographic operations.
#   You will also need to import functions to parse URLs and to support threading. 
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import threading # for threading lock
from urllib.parse import urlparse, parse_qs # to parse URLs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64 # For decoding the base64 signature from the client

from shamir import generate_shares, reconstruct, next_probable_prime_at_least, Share
TALLY_N_SHARES = 5 # total number of shares for each candidate's tally
TALLY_THRESHOLD = 3 # minimum shares required to reconstruct the tally
TALLY_SHAMIR_PRIME = next_probable_prime_at_least(1000) 


# Step 2: Create a threading lock to protect concurrent access to shared data and a simple shared state container with an initial value of CLOSED.
election_state_lock = threading.Lock()
ELECTION_STATE = {"status": "CLOSED"} # possible states "open" and "closed" for now..

# Step 3: Use a dictionary to store vote counts for each candidate. It should be held in memory and updated as votes are received.
# Your voting server should accept votes for three candidates: Alice, Bob and Charlie.
VOTE_COUNTS = {
    "Alice": 0,
    "Bob": 0,
    "Charlie": 0
}

# Allowed candidates list
ALLOWED_CANDIDATES = list(VOTE_COUNTS.keys())

TALLY_SHARES = {
    "Alice": [],
    "Bob": [],
    "Charlie": []
}

PUBLIC_KEYS_DB_FILE = "public_keys.json"
PUBLIC_KEYS_DATABASE = {} # will hold loaded public keys

# Load public keys database when the server starts
def _load_public_keys_database_on_demand():
    global PUBLIC_KEYS_DATABASE
    if os.path.exists(PUBLIC_KEYS_DB_FILE):
        with open(PUBLIC_KEYS_DB_FILE, "r") as f:
            try:
                updated_db = json.load(f)
                PUBLIC_KEYS_DATABASE = updated_db
                print(f"Reloaded public keys for voters: {list(PUBLIC_KEYS_DATABASE.keys())}")
            except json.JSONDecodeError:
                print(f"Error: {PUBLIC_KEYS_DB_FILE} is corrupted or empty. Public key database is empty after reload attempt.")
                PUBLIC_KEYS_DATABASE = {}
    else:
        print(f"Warning: {PUBLIC_KEYS_DB_FILE} not found. Public key database is empty after reload attempt.")
        PUBLIC_KEYS_DATABASE = {}

_load_public_keys_database_on_demand() # initial load on server startup

# Step 4: Initialize an empty list to hold incoming ballots. 
BALLOTS = []

# Step 5: Define a function to load the public key for a given voter ID from the registrar's database.
#   This key is used to verify the signature on the submitted vote.
def load_public_key_for_voter(voter_id):

    public_pem_str = PUBLIC_KEYS_DATABASE.get(voter_id)

    if public_pem_str is None:
        print(f"Error: Public key for voter ID '{voter_id}' not found in database.")
        return None

    try:
        public_key = serialization.load_pem_public_key(
            public_pem_str.encode('utf-8'),
            backend=default_backend()
        )
        return public_key

    except ValueError as e:
        print(f"Error loading public key for voter ID '{voter_id}': {e}")
        return None

# Step 6: Define a custom request handler class to manage incoming HTTP requests.
# It should handle POST requests.
class VotingServerHandler(BaseHTTPRequestHandler):
    # Write a function respond that:
    #   Sends a HTTP response to the client.
    #   It should set the HTTP status code (as input to the function).
    def respond(self, status_code, data=None, content_type='application/json'):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        if data:
            self.wfile.write(json.dumps(data).encode('utf-8'))

    # Write a function do_POST(self) that:
    #   Checks that the incoming request contains JSON data.
    #   Your function should accept votes only when election is open.
    #   Extract the candidate name and validate that the candidate is in the allowed list defined in step 3.
    #   Return an error response if the candidate is not in the allowed list.
    #   Check for any missing fields in the JSON data. Return an error response if any fields are missing.
    #   Verify the signature.
    #   If the candidate is in the allowed list, there are no missing fields, and the signature verifies, increment the vote count for that candidate and return a success message.
    def do_POST(self):
        # Admin can open and close election, as well as reload keys
        if self.path in ['/open', '/close', '/reload_keys']:
            self._handle_admin_post()
            return

        # Vote handling
        if self.path == '/vote':
            # Your function should accept votes only when election is open.
            with election_state_lock:
                if ELECTION_STATE["status"] != "OPEN":
                    self.respond(403, {"error": "Election is not open for voting."})
                    print("Rejected vote: Election is closed.")
                    return

            # Checks that the incoming request contains JSON data
            content_type = self.headers.get('Content-Type')
            if content_type != 'application/json':
                self.respond(400, {"error": "Content-Type must be application/json"})
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                request_data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.respond(400, {"error": "Invalid JSON format"})
                return

            voter_id = request_data.get('voter_id')
            candidate = request_data.get('candidate')
            sign_b64 = request_data.get('signature')

            # Check for any missing fields in the JSON data. Return an error response if any fields are missing.
            missing_fields = []
            if voter_id is None:
                missing_fields.append("voter_id")
            if candidate is None:
                missing_fields.append("candidate")
            if sign_b64 is None:
                missing_fields.append("signature")

            if missing_fields:
                self.respond(400, {"error": f"Missing required fields: {', '.join(missing_fields)}"})
                print(f"Rejected vote due to missing fields: {', '.join(missing_fields)}")
                return

            # Extract the candidate name and validate that the candidate is in the allowed list.
            # Return an error response if the candidate is not in the allowed list.
            if candidate not in ALLOWED_CANDIDATES:
                self.respond(400, {"error": f"Invalid candidate: {candidate}. Allowed candidates are: {', '.join(ALLOWED_CANDIDATES)}"})
                print(f"Rejected vote from {voter_id} due to invalid candidate: {candidate}")
                return

            # Verify the signature.
            public_key = load_public_key_for_voter(voter_id)
            if public_key is None:
                self.respond(400, {"error": f"Voter ID '{voter_id}' is not registered or public key is invalid. Please ensure keys are registered and reloaded."})
                return

            try:
                signature = base64.b64decode(sign_b64)
            except (base64.binascii.Error, TypeError):
                self.respond(400, {"error": "Invalid signature format (not valid base64)."})
                print(f"Rejected vote from {voter_id} due to invalid signature format.")
                return

            # Reconstruct the message that was signed by the client (must be identical)
            message_to_verify = f"{voter_id},{candidate}".encode('utf-8')

            try:
                public_key.verify(
                    signature,
                    message_to_verify,
                    ec.ECDSA(hashes.SHA256())
                )
                # If the candidate is in the allowed list, there are no missing fields, and the signature verifies,
                # increment the vote count for that candidate and return a success message.
                with election_state_lock: # Protect VOTE_COUNTS and BALLOTS access
                    VOTE_COUNTS[candidate] += 1
                    BALLOTS.append(request_data) # Store the ballot for auditing

                print(f"VALID vote recorded from {voter_id} for: {candidate}. Current tally: {VOTE_COUNTS[candidate]}")
                self.respond(200, {"message": f"Vote for {candidate} successfully recorded from voter {voter_id}."})
            
            except InvalidSignature:
                print(f"INVALID signature from {voter_id} for: {candidate}. Vote rejected.")
                self.respond(401, {"error": "Invalid signature. Vote rejected."}) # Unauthorized
            
            except Exception as e:
                print(f"An unexpected error occurred during signature verification: {e}")
                self.respond(500, {"error": f"Internal server error during signature verification: {str(e)}"})

        else:
            self.respond(404, {"error": "Endpoint not found"})

    def _handle_admin_post(self):

        global TALLY_SHARES
        global VOTE_COUNTS

        content_length = int(self.headers['Content-Length']) if 'Content-Length' in self.headers else 0
        
        if content_length > 0:
            self.rfile.read(content_length) # discard body

        with election_state_lock:
            current_status = ELECTION_STATE["status"]
            if self.path == '/open':
                if current_status == "OPEN":
                    self.respond(200, {"message": "Election is already open."})
                
                else:
                    ELECTION_STATE["status"] = "OPEN" # reset vote counts on new election
                    for candidate in VOTE_COUNTS:
                        VOTE_COUNTS[candidate] = 0
                        TALLY_SHARES[candidate] = [] # clear previous shares
                    BALLOTS.clear()
                    self.respond(200, {"message": "Election opened successfully."})
                    print("ADMIN: Election state changed to OPEN. Vote counts reset.")
            
            elif self.path == '/close':
                if current_status == "CLOSED":
                    self.respond(200, {"message": "Election is already closed."})
                
                else:
                    ELECTION_STATE["status"] = "CLOSED"
                    # Generate Shamir shares for final vote counts for each candidate
                    for candidate, count in VOTE_COUNTS.items():
                        TALLY_SHARES[candidate] = generate_shares(
                            count, TALLY_N_SHARES, TALLY_THRESHOLD, TALLY_SHAMIR_PRIME
                            )
                    
                    self.respond(200, {"message": "Election closed successfully."})
                    print("ADMIN: Election state changed to CLOSED.")
            
            elif self.path == '/reload_keys':
                _load_public_keys_database_on_demand()
                self.respond(200, {"message": "Public keys database reloaded."})
                print("ADMIN: Public keys database reloaded by explicit request.")
            
            else:
                self.respond(404, {"error": "Admin endpoint not found."})

    # Write a function do_GET(self) that:
    #   Handles GET requests used to retrieve the current vote results.
    #   Your function should retrieve the current election status and only return the result if the election is closed. 
    #   It should check that the request is targeting the /results endpoint and respond with the current vote tally in JSON format.
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)

        if path == '/status':
            with election_state_lock:
                self.respond(200, ELECTION_STATE)
                print(f"Status requested. Current state: {ELECTION_STATE['status']}")
        
        elif path == '/results':
            with election_state_lock:
                
                if ELECTION_STATE["status"] != "CLOSED":
                    self.respond(403, {"error": "Results can only be retrieved when the election is closed."})
                    print("Rejected results request: Election is open.")
                    return
                
                self.respond(200, { # Inform client that results are secured by Shamir SS
                    "message": f"Election results are secured using Shamir Secret Sharing ({TALLY_THRESHOLD} of {TALLY_N_SHARES} shares required).",
                    "instructions": "An authorized tallier must reconstruct the results using shares retrieved from /get_tally_shares."
                })
                print("Results requested. Informed client about Shamir SS.")
            
        elif path == '/get_tally_shares':
            with election_state_lock:
                if ELECTION_STATE["status"] != "CLOSED":
                    self.respond(403, {"error": "Tally shares can only be retrieved when the election is closed."})
                    print("Rejected tally share request: Election is open.")
                    return
                
                share_id_str = query_params.get('share_id')
                if not share_id_str:
                    self.respond(400, {"error": "Missing 'share_id' query parameter."})
                    return

                try:
                    requested_share_id = int(share_id_str[0])
                    if not (1 <= requested_share_id <= TALLY_N_SHARES):
                        raise ValueError
                
                except (ValueError, IndexError):
                    self.respond(400, {"error": f"'share_id' must be an integer between 1 and {TALLY_N_SHARES}."})
                    return

                # Collect shares for all candidates for the requested share_id
                shares_for_id = {}
                for candidate, candidate_shares in TALLY_SHARES.items():
                    if requested_share_id - 1 < len(candidate_shares):
                        shares_for_id[candidate] = candidate_shares[requested_share_id - 1] [1]
                    
                    else:
                        self.respond(500, {"error": f"Server error: Share ID {requested_share_id} not found for candidate {candidate}."})
                        return
                    
                self.respond(200, {"share_id": requested_share_id, "candidate_tally_shares": shares_for_id, "message": f"Shamir share {requested_share_id} retrieved for all candidate tallies."})
                print(f"Tally share {requested_share_id} requested and returned.")
            
        else:
            self.respond(404, {"error": "Endpoint not found"})
        
# Step 7: Write a function that sets up and runs the HTTP server.
# It should bind to localhost on port 5000.
# It should run until manually stopped.
def run_server(server_class=HTTPServer, handler_class=VotingServerHandler, port=5000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}...")

    print(f"Shamir Secret Sharing for Tally: N_SHARES={TALLY_N_SHARES}, "
          f"THRESHOLD={TALLY_THRESHOLD}, PRIME={TALLY_SHAMIR_PRIME}")
    # It should run until manually stopped.
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Stopping server.")

if __name__ == '__main__':
    run_server()