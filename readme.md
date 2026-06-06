# Secure E-Voting System

A client-server electronic voting system in Python that combines digital signatures for
vote authentication with Shamir's Secret Sharing for threshold-based tally reconstruction.
Built for the Advanced Cybersecurity module (SCC.351) at Lancaster University.

## Overview

The system models an election with three roles: a registrar that issues voter keys, a
server that receives and verifies signed votes, and an admin that runs the election and
reconstructs the final tally. The goal was to apply real cryptographic primitives to the
security requirements of voting: only eligible voters can vote, votes cannot be forged or
altered, nobody can vote twice, and the final result cannot be revealed by any single party
acting alone.

## Security features

- **Voter authentication and integrity:** each voter signs their ballot with an ECDSA
  private key (NIST P-256 / SECP256R1, SHA-256). The server verifies the signature against
  the voter's registered public key before counting the vote.
- **Eligibility and double-vote prevention:** only registered voters with a valid key can
  vote, and repeat votes from the same voter are rejected.
- **Threshold tally reconstruction:** the final tally is secret-shared with Shamir's Secret
  Sharing (5 shares, threshold of 3). Reconstructing the result requires a quorum, so no
  single party can compute the outcome alone.
- **Tamper detection:** invalid or modified shares produce an incorrect reconstruction,
  demonstrated in the Shamir test routine.

## Cryptography

- **Shamir's Secret Sharing, implemented from scratch:** polynomial generation over a prime
  field, modular arithmetic, and Lagrange interpolation to recover the secret at f(0).
- **Miller-Rabin primality testing** to generate the prime modulus.
- **ECDSA** is provided by the audited `cryptography` library rather than a custom
  implementation, following the principle of not writing your own production crypto.

## Components

- `registrar.py`: generates per-voter ECDSA key pairs and publishes the public-key database.
- `server.py`: receives votes, verifies signatures, tracks the election state, and produces
  the secret-shared tally.
- `client.py`: voter-facing CLI to sign and submit a vote and to view published results.
- `admin.py`: opens/closes the election, checks status, and reconstructs and publishes the tally.
- `shamir.py`: standalone Shamir Secret Sharing implementation with a self-test demo.

## Running

The included script runs a full end-to-end election (register voters, open, cast votes,
reject a double vote, close, reconstruct, publish, view results):

​```bash
./test_script.sh
​```

To run components individually:

​```bash
pip install cryptography requests
python3 server.py            # start the server
python3 registrar.py         # register voters
python3 admin.py open        # open the election
python3 client.py            # cast a vote
python3 admin.py reconstruct_tally   # reconstruct and publish the tally
​```

`cleanup.sh` removes generated keys and stops the server.

## Scope

This is an educational project. Parameters such as the small tally prime, unencrypted local
key storage, and plain HTTP are appropriate for a coursework demo but would need hardening
for any real deployment.