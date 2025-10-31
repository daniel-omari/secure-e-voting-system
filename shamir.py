# Step 1: Import modules for handling simple random choices and sampling.
import random
from typing import List, Tuple

# Step 2: Define 'Share' as a tuple of two integerss to represent a secret share (index, value).
Share = Tuple[int, int]

# Step 3: Define a function 'eval_polynomial' that evaluates a polynomial f(x) = s + f1*x^1 + f2*x^2 + ... + ft-1*x^{t-1} at a point x (modulo a prime).
#   The function will be called in function generate_shares. 
#   Your function should take as input:
#       1. a list of coefficients 'coeffs'. The coefficients list coeffs is ordered so coeffs[0] is the constant term (i.e., secret s), coeffs[1] is f1, coeffs[2] is f2 and so on. 
#       2. an integer 'x' (the point at which the polynomial will be evaluated)
#       3. a prime number 'p' 
#   Initialise two variables:
#       1. 'result' will accumulate the value of the polynomial at point x. It should start at 0.
#       2. 'power' will hold successive powers of x, beginning at x**0 = 1. 
#   Evaluate the polynomial by looping through each coefficient c in coeffs:
#       1. Multiply c by the current power and add to 'result'.
#       2. Update the power by multiplying it by x.
#       3. After the loop, return the result.
#       4. Remember to perform all computations modulo prime p.
def eval_polynomial(coeffs: List[int], x: int, p: int) -> int:
    result = 0
    power = 1
    for c in coeffs:
        result = (result + (c * power) % p) % p
        power = (power * x) % p
    return result

# Step 4: Define a function 'generate_shares' that will generate n shares.
#   Your function should take as input:
#       1. the secret to be shared 'secret'
#       2. the number of shares to be created 'n'
#       3. the threshold 't'
#       4. prime number 'p'
#   Construct a ranadom polynomial of degree t-1. 
#       Your polynomial will be defined by its list of coefficients 'coeffs'
#       Define coeffs[0] = secret
#       For 1,...,t-1, the coefficient should be a random value chosen from the range 0,...,prime-1.
#   Produce shares by evaluating the polynomial at x = 1,...,n. 
#       That is, for each i = 1,...,n, compute y = f(i) using eval_polynomial. 
#       Store each share as a tuple (i, y) in a list. 
#   Return the list of shares.
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

# The following function reconstructs the polynomial for a list of shares. 
# It uses a method callled Lagrange interpolation to compute f(0) given a list of shares. 
# It takes as input:
#   1. a list of elements 'i' incidcating which shares are being combined.
#   2. a list of elements 'y', which are the shares corresponding to the 'i' indices. 
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

# Step 5: Define a function 'reconstruct' that will return the secret from a list of provided shares.
#   Your function should take as input:
#       1. a list of shares 'List'
#       2. prime 'p'
#   Separate the input list of tuples returned by generate_shares into two lists:
#       1. x_s that will hold the first element of each tuple, the participants 'i' value
#       2. y_s which will hold the corresponding share value
#   Call function lagrange_interpolate_at_zero
#   Return the secret
def reconstruct(shares_subset: List[Share], p: int) -> int:
    if not shares_subset:
        raise ValueError("Cannot reconstruct secret from an empty list of shares.")
    if len(shares_subset) < 2:
        raise ValueError("Need at least 2 shares for Lagrange interpolation.")

    x_s = [share[0] for share in shares_subset]
    y_s = [share[1] for share in shares_subset]

    return lagrange_interpolate_at_zero(x_s, y_s, p)

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


def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate

# Step 6: Define a dunction demo() that will run and perform basic tests on your code. 
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

#   Reconstruct the secret from first t shares and print the result. 
    try_reconstruct(
        all_shares[:t],
        f"2. Reconstructing with exactly {t} shares (first {t} shares)"
    )

#   Reconstruct the secret from an arbitrary subset of t shares. Print the result. 
    arbitrary_shares = [all_shares[1], all_shares[3], all_shares[4]]
    try_reconstruct(
        arbitrary_shares,
        f"3. Reconstructing with an arbitrary subset of {t} shares"
    )

#   Attempt to reconstruct the secret with fewer than t shares.
    fewer_shares = all_shares[:t-1] # Use t-1 shares
    try_reconstruct(
        fewer_shares,
        f"4. Attempting reconstruction with fewer than {t} shares (t-1 shares)",
        expected_match=False # We expect it NOT to match, or to raise an error
    )

#   Tamper a share and show that it returns a wrong value.
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
