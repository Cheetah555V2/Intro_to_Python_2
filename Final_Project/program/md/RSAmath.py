import primitive_test as pt
import random
import math
import RSAerror as RSAE

def gen_prime(digits: int = 310) -> int:
    try:
        while True:
            p = random.randint(10 ** (digits + 1), (10 ** (digits + 2)) -1)
            if pt.is_prime(p, 64):
                return p
    except Exception as error:
        raise RSAE.PrimeGenerationError(f'Prime generation failed {error}')

def modular_multiplicative_inverse(multiplyer: int,
                                   modulus_base: int) -> int:
    """
    multiplyer   : int
    modulus_base : int

    return an inverse of modulur multiplicative inverse

    multiplyer*x ≡ 1 (mod modulus_base)

    Then x ≡ multiplyer^(-1) (mod modulus_base)

    this function find x and return it
    """

    if math.gcd(multiplyer, modulus_base) != 1:
        return 0  # 0 for false since number*0 !≡ 1 (mod anything)

    # Use Extended Euclidean algorithm

    remainder_curr = modulus_base
    remainder_next = multiplyer

    bezout_coefficients_curr = 0
    bezout_coefficients_next = 1

    while remainder_next != 0:
        quotient = remainder_curr // remainder_next

        bezout_coefficients_curr, bezout_coefficients_next = \
            bezout_coefficients_next, bezout_coefficients_curr - \
            (quotient * bezout_coefficients_next)

        remainder_curr, remainder_next = \
            remainder_next, remainder_curr - (quotient * remainder_next)

    if bezout_coefficients_curr < 0:
        bezout_coefficients_curr += modulus_base

    return bezout_coefficients_curr

def public_exponent_generator(euler_totient: int) -> int:
    """
    euler_totient : int

    find and e that gcd(e,euler_totient) = 1
    return e
    """
    if euler_totient > 65537:
        public_exponent = 65537
    else:
        public_exponent = random.randint(2, euler_totient-1)

    while math.gcd(public_exponent, euler_totient) != 1:
        public_exponent = random.randint(2, euler_totient-1)

    return public_exponent

def private_exponent_finder(exponent: int,
                            totient: int) -> int:
    """
    exponent : int
    prime_1  : int (prime number)
    prime_2  : int (prime number)

    let n = prime_1*prime_2
    find d such that exponent*d ≡ 1 (mod ϕ(n))

    return d
    """

    private_exponent = modular_multiplicative_inverse(exponent, totient)
    if private_exponent == 0:
        return 0
    return private_exponent