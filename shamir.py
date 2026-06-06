import random
from typing import List, Tuple

# A secret share: (x-index, f(x) value).
Share = Tuple[int, int]

# Evaluate polynomial f(x) at point x, modulo prime p.
# coeffs[0] is the secret (constant term); the rest are the random coefficients.
def eval_polynomial(coeffs: List[int], x: int, p: int) -> int:
    result = 0
    power = 1
    for c in coeffs:
        result = (result + (c * power) % p) % p
        power = (power * x) % p
    return result

# Split `secret` into n shares with a recovery threshold of t, over prime field p.
# Builds a random degree-(t-1) polynomial whose constant term is the secret,
# then samples it at x = 1..n.
def generate_shares(secret: int, n: int, t: int, p: int) -> List[Share]:
    if t > n:
        raise ValueError("Threshold (t) cannot be greater than the number of shares (n).")
    if secret >= p or secret < 0:
        raise ValueError("Secret must be in the range [0, p-1].")

    coeffs = [secret] + [random.randint(0, p - 1) for _ in range(t - 1)]

    shares = []
    for i in range(1, n + 1):
        y = eval_polynomial(coeffs, i, p)
        shares.append((i, y))
    return shares

# Recover f(0) (the secret) from a set of shares using Lagrange interpolation.
def lagrange_interpolate_at_zero(x_s: List[int], y_s: List[int], prime: int) -> int:
    assert len(x_s) == len(y_s), "x_s and y_s must have the same length"
    k = len(x_s)
    total = 0
    for j in range(k):
        xj, yj = x_s[j], y_s[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = x_s[m]
            num = (num * (-xm)) % prime      
            den = (den * (xj - xm)) % prime
        
        if den < 0:
            den += prime
        inv_den = pow(den, -1, prime)
        lj = (num * inv_den) % prime
        total = (total + yj * lj) % prime
    return total

# Reconstruct the secret from any t-or-more shares.
def reconstruct(shares_subset: List[Share], p: int) -> int:
    if not shares_subset:
        raise ValueError("Cannot reconstruct secret from an empty list of shares.")
    if len(shares_subset) < 2:
        raise ValueError("Need at least 2 shares for Lagrange interpolation.")

    x_s = [share[0] for share in shares_subset]
    y_s = [share[1] for share in shares_subset]

    return lagrange_interpolate_at_zero(x_s, y_s, p)

# Miller-Rabin probabilistic primality test.
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

# Smallest probable prime >= m, used to size the field for secret sharing.
def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate

# Self-test: share a secret, reconstruct from valid quorums, and show that
# too-few shares or a tampered share fail to recover it.
def demo():

    """
    Demonstrates Shamir Secret Sharing:
    - Generates shares for a secret.
    - Reconstructs with sufficient shares (two successful cases).
    - Shows failure with insufficient shares.
    - Shows failure with a tampered share.
    """

    # You can use the values below to test your code. 
    prime = 2**127 - 1
    secret = 42
    n = 6
    t = 3

    print(f"\nConfiguration: Secret={secret}, n={n} shares, t={t} threshold, Prime={prime}")

#   Generate shares and print the shares.
    all_shares = generate_shares(secret, n, t, prime)
    print("\nGenerated Shares:")
    for i, (idx, val) in enumerate(all_shares):
        print(f" Share {idx}: {val}")

    def try_reconstruct(shares_to_use: List[Share], description: str, expected_match: bool = True):
        print(f"\n- {description}:")
        print(f"  Shares used ({len(shares_to_use)} shares): {shares_to_use}")
        try:
            reconstructed_val = reconstruct(shares_to_use, prime)
            print(f"  Reconstructed secret: {reconstructed_val}")
            is_match = (reconstructed_val == secret)
            print(f"  Matches original secret? {is_match} (Expected: {expected_match})")
            if is_match != expected_match:
                print("  WARNING: Unexpected result!")
        except ValueError as e:
            print(f"  Reconstruction failed: {e}")
            if expected_match:
                print("  WARNING: Unexpected failure!")

#   Reconstruct from the first t shares and print the result. 
    try_reconstruct(
        all_shares[:t],
        f"2. Reconstructing with exactly {t} shares (first {t} shares)"
    )

#   Reconstruct from an arbitrary subset of t shares. Print the result. 
    arbitrary_shares = [all_shares[1], all_shares[3], all_shares[4]]
    try_reconstruct(
        arbitrary_shares,
        f"3. Reconstructing with an arbitrary subset of {t} shares"
    )

#   Fewer than t shares: should not recover the secret.
    fewer_shares = all_shares[:t-1] # Use t-1 shares
    try_reconstruct(
        fewer_shares,
        f"4. Attempting reconstruction with fewer than {t} shares (t-1 shares)",
        expected_match=False # We expect it NOT to match, or to raise an error
    )

#   Tampered share: should produce a wrong result.
    tampered_shares = list(all_shares[:t]) # Make a copy of first 't' shares
    # Choose a share to tamper, e.g., the first one
    original_val = tampered_shares[0][1]
    tampered_shares[0] = (tampered_shares[0][0], (tampered_shares[0][1] + 100) % prime) # Tamper value
    
    print(f"\n- 5. Attempting reconstruction with a tampered share:")
    print(f"  Shares used (first share tampered from {original_val} to {tampered_shares[0][1]}): {tampered_shares}")
    try:
        reconstructed_val = reconstruct(tampered_shares, prime)
        print(f"  Reconstructed secret: {reconstructed_val}")
        is_match = (reconstructed_val == secret)
        print(f"  Matches original secret? {is_match} (Expected: False)")
        if is_match:
            print("  WARNING: Tampered share unexpectedly returned the correct secret!")
    except ValueError as e:
        print(f"  Reconstruction failed: {e} (This is unexpected for tampered shares if 't' shares are provided.)")
    print("\n--- Demo Complete ---")

if __name__ == '__main__':
    demo()
