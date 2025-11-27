import random, math
import RSAerror as rsae

def trial_division_primitive_test(number: int) -> bool:
    """
    number : int
    Try to divided a number up to sqrt(number) + 1
    if there exist an integer that can divided number
        return False
    else
        return True 
    """
    try:
        if number <= 1:
            return False
        for index in range(2, int(math.sqrt(number)) + 1):
            if number % index == 0:
                return False
        return True
    except Exception as error:
        raise rsae.RSAError(f'Trial division failed {error}')


def miller_rabin_primitive_test(number: int, iterations: int = 10) -> bool:
    """
    number     : int
    iterations : int
    """

    """
    witness^(2^k) ≡ 1 (mod p) if p is prime satisfy 2 conditions
    1. Sequence (a_k) ends with 1 (Fermar's test)
    2. Sequence (a_k) before 1 must be 1 or n - 1
    """

    """
    Miller Robin primitive test is prob test for prime
    1. Find s > 0 and odd d > 0 such that number - 1 = 2^s * d
    2. Repeat iterations times:
        2.1 witness <- random(2, n-2)
        2.2 curr_sequence <- witness^d mod n
        2.3 Repeat s times:
            2.3.1 next_sequence <- curr_sequence^2 mod n
            2.3.2 if y = 1 and x != 1 and x != n-1:
                2.3.2.1 return "composite"
            2.3.3 curr_sequence <- next_sequence
        2.4 if next_sequence != 1:
            2.4.1 return "composite"
    3. return "probably prime"
    """
    try:
        # edge cases

        if number == 2 or number == 3:
            return True

        if number <= 1 or number % 2 == 0:
            return False

        # find s > 0 and odd number d > 0 such that number-1 = 2^s * d

        power_of_two_factor = 0             # s
        odd_factor = number - 1             # d
        while odd_factor % 2 == 0:
            odd_factor //= 2
            power_of_two_factor += 1

        for _ in range(iterations):
            witness = random.randint(2, number - 2)

            # x^d mod n
            curr_sequnce = pow(witness, odd_factor, number)

            if curr_sequnce == 1 or curr_sequnce == number - 1:
                continue
                # If p is prime then x^2 ≡ 1 mod(p) then x ≡ 1 or x ≡ p - 1
                # So no need to check since sequnce the come after this will
                # also be 1 or p - 1

            for _ in range(power_of_two_factor):
                # next sequence = x^2 mod n
                next_sequnce = (curr_sequnce * curr_sequnce) % number

                # Check if x = 1 or x = n-1 iff next sequence is x^2 = 1?
                if (next_sequnce == 1) and (curr_sequnce != 1) and \
                        (curr_sequnce != number - 1):
                    return False

                # x = next sequence
                curr_sequnce = next_sequnce

            if next_sequnce != 1:
                return False

        return True
    except Exception as error:
        raise rsae.RSAError(f'Miller-Rabin test failed: {error}')


def is_prime(number: int, accuracy_level: int = 10) -> bool:
    """
    number         : int
    accuracy_level : int

    If number > 10^12 
        return result of Miller Rabin primitive test with
        accuracy_level iterations
        (return True or False)
    else
        return result of trial division primitive test
        (return True or False)

    """
    try:    
        if number > 10**12:
            return miller_rabin_primitive_test(number, accuracy_level)

        return trial_division_primitive_test(number)
    except Exception as error:
        raise rsae.RSAError(f'Primitive test failed: {error}')