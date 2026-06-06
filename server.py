# Voting server: HTTP API, JSON handling, ECDSA verification, URL parsing and threading.
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time # for rate limiting
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
PUBLIC_FINAL_TALLY = None


# Lock guarding all shared mutable state against concurrent requests; election starts CLOSED.
election_state_lock = threading.Lock()
ELECTION_STATE = {"status": "CLOSED"} # possible states "open" and "closed" for now..

# In-memory vote tally. The election runs with three fixed candidates.
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

LAST_REQUEST_TIME = {} # keep track the last request time for each voter_id
RATE_LIMIT_SECONDS = 0.5 # allow one request per voter_id every 0.5 sec (protection against DoS attacks)

# Load (or reload) the registrar's public-key database from disk.
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

# Voter IDs that have already cast a valid vote, used to prevent double voting.
VOTED_IDS = set()

# Audit log of accepted ballots.
BALLOTS = []

# Load and deserialize a voter's public key for signature verification.
# Returns None if the voter is unknown or the stored key is invalid.
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

# HTTP handler for the voting API: vote submission, admin actions, and status/results endpoints.
class VotingServerHandler(BaseHTTPRequestHandler):
    # Send a JSON HTTP response with the given status code.
    def respond(self, status_code, data=None, content_type='application/json'):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        if data:
            self.wfile.write(json.dumps(data).encode('utf-8'))

    #   Route POST requests: admin actions (/open, /close, /reload_keys), vote casting, and tally publication.
    #   A vote is accepted only if the election is open, all fields are present, the candidate is valid,
    #   and the ECDSA signature verifies against the voter's registered public key.
    def do_POST(self):
        # Admin can open and close election, as well as reload keys
        if self.path in ['/open', '/close', '/reload_keys']:
            self._handle_admin_post()
            return

        # Vote handling
        if self.path == '/vote':
            # Only accept votes while the election is OPEN.
            with election_state_lock:
                if ELECTION_STATE["status"] != "OPEN":
                    self.respond(403, {"error": "Election is not open for voting."})
                    print("Rejected vote: Election is closed.")
                    return

            # Require a JSON body.
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

            # Reject the request if any required field is missing.
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

            # Rate-limit per voter to throttle rapid repeat requests (basic DoS protection).
            current_time = time.time()
            if voter_id in LAST_REQUEST_TIME:
                time_since_last_request = current_time - LAST_REQUEST_TIME[voter_id]

                if time_since_last_request < RATE_LIMIT_SECONDS:
                    self.respond(429, {"error": f"Rate limit exceeded for voter_id '{voter_id}'. Please wait {RATE_LIMIT_SECONDS - int(time_since_last_request)} seconds."})
                    print(f"Rejected vote from {voter_id} due to rate limit (DoS protection).")
                    return

            LAST_REQUEST_TIME[voter_id] = current_time # update last request time for this voter

            # Reject unknown candidates.
            if candidate not in ALLOWED_CANDIDATES:
                self.respond(400, {"error": f"Invalid candidate: {candidate}. Allowed candidates are: {', '.join(ALLOWED_CANDIDATES)}"})
                print(f"Rejected vote from {voter_id} due to invalid candidate: {candidate}")
                return

            # Verify the ECDSA signature against the voter's registered public key.
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

            # Rebuild the exact message the client signed; it must match byte-for-byte.
            message_to_verify = f"{voter_id},{candidate}".encode('utf-8')

            try:
                public_key.verify(
                    signature,
                    message_to_verify,
                    ec.ECDSA(hashes.SHA256())
                )
                # Signature valid: record the vote and keep the ballot for auditing.
                with election_state_lock: # Protect VOTE_COUNTS, BALLOTS and VOTED_IDS access
                    # Reject a second vote from a voter who has already voted.
                    if voter_id in VOTED_IDS:
                        self.respond(409, {"error": f"Voter '{voter_id}' has already voted."})
                        print(f"Rejected duplicate vote from {voter_id}.")
                        return
                    VOTE_COUNTS[candidate] += 1
                    VOTED_IDS.add(voter_id)
                    BALLOTS.append(request_data) # Store the ballot for auditing

                print(f"VALID vote recorded from {voter_id} for: {candidate}. Current tally: {VOTE_COUNTS[candidate]}")
                self.respond(200, {"message": f"Vote for {candidate} successfully recorded from voter {voter_id}."})
            
            except InvalidSignature:
                print(f"INVALID signature from {voter_id} for: {candidate}. Vote rejected.")
                self.respond(401, {"error": "Invalid signature. Vote rejected."}) # Unauthorized
            
            except Exception as e:
                print(f"An unexpected error occurred during signature verification: {e}")
                self.respond(500, {"error": f"Internal server error during signature verification: {str(e)}"})
        
        elif self.path == '/publish_tally':
            content_type = self.headers.get('Content-Type')
            if content_type != 'application/json':
                self.respond(400, {"error": "Content-Type must be application/json"})
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                published_tally = json.loads(post_data.decode('utf-8'))
                if not isinstance(published_tally, dict) or not all(c in published_tally for c in ALLOWED_CANDIDATES):
                    self.respond(400, {"error": "Invalid tally format. Expected JSON object with candidate votes."})
                    return

            except json.JSONDecodeError:
                self.respond(400, {"error": "Invalid JSON format for tally."})
                return

            with election_state_lock:
                if ELECTION_STATE["status"] != "CLOSED":
                    self.respond(403, {"error": "Tally can only be published when election is CLOSED."})
                    return
            
                global PUBLIC_FINAL_TALLY
                PUBLIC_FINAL_TALLY = published_tally
                self.respond(200, {"message": "Final tally successfully published."})
                print(f"ADMIN: Final tally published: {PUBLIC_FINAL_TALLY}")

        else:
            self.respond(404, {"error": "Endpoint not found"})

    def _handle_admin_post(self):

        global TALLY_SHARES
        global VOTE_COUNTS
        global LAST_REQUEST_TIME # clear rate limit tracker when election opens

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
                    VOTED_IDS.clear() # let voters vote again in the new election
                    LAST_REQUEST_TIME.clear() # clear rate limit tracker
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

                    global PUBLIC_FINAL_TALLY
                    PUBLIC_FINAL_TALLY = None # clear any previously published tally when election closes
                    
                    self.respond(200, {"message": "Election closed successfully."})
                    print("ADMIN: Election state changed to CLOSED. Tally shares generated.")
            
            elif self.path == '/reload_keys':
                _load_public_keys_database_on_demand()
                self.respond(200, {"message": "Public keys database reloaded."})
                print("ADMIN: Public keys database reloaded by explicit request.")
            
            else:
                self.respond(404, {"error": "Admin endpoint not found."})

    # Route GET requests: /status, /results (only once CLOSED and published), and /get_tally_shares.
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

                global PUBLIC_FINAL_TALLY
                if PUBLIC_FINAL_TALLY is None:
                    self.respond(200, {
                        "message": f"Election results are secured using Shamir Secret Sharing ({TALLY_THRESHOLD} of {TALLY_N_SHARES} shares required).",
                        "instructions": "The administrator must reconstruct the results and then publish them before they are viewable here."
                    })
                    print("Results requested. Tally not yet published by admin.")
                
                else:
                    self.respond(200, {
                        "message": "Final Election Tally (Published by Administrator):",
                        "tally": PUBLIC_FINAL_TALLY
                    })
                    print(f"Results requested. Publicly published tally returned: {PUBLIC_FINAL_TALLY}")
            
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
        
# Start the HTTP server on localhost:5000 and run until interrupted.
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