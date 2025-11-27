import math
import os
import time
import random


"""
|==============================================
|              Console commmand
|==============================================
"""

if os.name == "nt":
    import msvcrt

    def clear_console() -> None:
        # Use clear console command
        os.system("cls")

    def get_char() -> str:
        # Output 1 character then user type without echo and waiting for enter
        return chr(msvcrt.getch()[0])

else:
    import tty
    import termios
    import sys

    def clear_console() -> None:
        os.system("clear")

    def get_char() -> str:
        # Gets the file descriptor (an integer handle) for standard input
        file_descriptor = sys.stdin.fileno()

        # Saves the current terminal settings
        old_settings = termios.tcgetattr(file_descriptor)

        # Puts the terminal in raw mode (No echo)
        tty.setraw(file_descriptor)

        # Reads 1 character from the terminal
        character = sys.stdin.read(1)

        # Restores the original terminal settings
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, old_settings)

        # return character
        return character


"""
|==============================================
|                Primitive test
|==============================================
"""


def trial_division_primitive_test(number: int) -> bool:
    """
    number : int
    Try to divided a number up to sqrt(number) + 1
    if there exist an integer that can divided number
        return False
    else
        return True 
    """

    if number <= 1:
        return False

    for index in range(2, int(math.sqrt(number)) + 1):
        # math.sqrt() is faster then x ** (1/2), I read the c and assembly code
        # it's like 20 times faster and more accurate
        # math.sqrt() is just 1 instruction in x86 (modern CPU with SSE2)

        if number % index == 0:
            return False

    return True


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

    if number > 10**12:
        return miller_rabin_primitive_test(number, accuracy_level)

    return trial_division_primitive_test(number)


"""
|==============================================
|                 Math function
|==============================================
"""


def RSA_encryption(unicode: int,
                   public_exponent: int,
                   modulus: int) -> int:
    """
    unicode         : int
    public_exponent : int
    modulus         : int

    it's just return unicode^public_exponent % modulus
    """

    return pow(unicode, public_exponent, modulus)


def RSA_decryption(encrypt_code: int,
                   private_exponent: int,
                   modulus: int) -> int:
    """
    encrypt_code     : int
    private_exponent : int
    modulus          : int

    it's just return encrypt_code^private_exponent % modulus
    """

    return pow(encrypt_code, private_exponent, modulus)


def semiprime_euler_totient(prime_1: int, prime_2: int) -> int:
    """
    prime_1 : int (prime number)
    prime_2 : int (prime number)

    ϕ(n) is Euler's totient function which output the amount of coprime
    relative to n

    And ϕ(n) has a property which is if n = p_1^{k_1}p_2^{k_2}... (p is prime)
    then ϕ(n) = ϕ(p_1^{k_1})ϕ(p_2^{k_2})...
    and ϕ(p^k) = p^{k-1}(p-1)

    then ϕ(n) = p_1^{k_1-1}(p_1-1)p_2^{k_2-1}(p_2-1)...

    since our number is semi prime then

    ϕ(number) = (prime_1 - 1)(prime_2 - 1)

    and then we return ϕ(number)
    """
    return (prime_1-1) * (prime_2-1)


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


"""
|==============================================
|             Sub-Sub-Main function
|==============================================
"""


def generating_prime(digits: int) -> int:
    """
    digits : int

    return a prime number with input numbers of digits
    """
    number = random.randint(10**(digits-1), 10**(digits)-1)
    while not is_prime(number):
        number = random.randint(10**(digits-1), 10**(digits)-1)

    return number


def wait_for_right_input_receiver(*wanted_input: str) -> str:
    """
    *wanted_input : character (1 character string)

    Will run until user type 1 of the wanted_input
    then return the last character that user type
    """
    choice = get_char().lower()
    while choice not in wanted_input:
        choice = get_char().lower()

    return choice


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
                            prime_1: int,
                            prime_2: int) -> int:
    """
    exponent : int
    prime_1  : int (prime number)
    prime_2  : int (prime number)

    let n = prime_1*prime_2
    find d such that exponent*d ≡ 1 (mod ϕ(n))

    return d
    """

    totient = semiprime_euler_totient(prime_1, prime_2)
    private_exponent = modular_multiplicative_inverse(exponent, totient)
    if private_exponent == 0:
        return 0
    return private_exponent


"""
|==============================================
|               Sub-Main function
|==============================================
"""


def check_for_primality_flow() -> None:
    while True:

        clear_console()
        print("Primality Test\nEnter an integer to test for primality: ")

        number = int(input())

        clear_console()

        if number > 10**12:
            # Use Miller-Rabin for large numbers
            print("""Miller-Rabin Primality Test Selected for this number.
Please provide a accuracy level that you want in positive integer (1-20) (defa\
lut = 10): """)
            accuracy_level = input()
            if accuracy_level.isdigit():
                accuracy_level = int(accuracy_level)
            else:
                accuracy_level = 10

            print("Processing... please wait.")

            start_time = time.time()
            result = is_prime(number, accuracy_level)
            end_time = time.time()
            elapsed_time = end_time - start_time
            accuracy = max(0, (1 - (1 / (4**accuracy_level))) * 100)  # in %

            clear_console()

            if result:
                print(f"""The number {number}\nis Probabliy Prime with \
{accuracy}% confidence""")
                print(f"The program took {elapsed_time:.6f} to complete.")
                print("""Do you want to check if it's definitely prime? This m\
ight take up a lot of time (use trial division up to √number) (Y/N):""")

                choice = wait_for_right_input_receiver("y", "n")

                clear_console()

                if choice == "y":
                    clear_console()

                    print("Processing... please wait.")
                    start_time = time.time()
                    result = trial_division_primitive_test(number)
                    end_time = time.time()
                    elapsed_time = end_time - start_time

                    clear_console()

                    if result:
                        print(f"The number {number} is Prime")
                    else:
                        print(f"The number {number} is Composite")

                    print(f"The program took {elapsed_time:.6f} to complete.")

            else:
                print(f"The number {number} is Composite")
                print(f"The program took {elapsed_time:.6f} seconds to complet\
e.")

        else:
            # Use trial division for small numbers
            print("Processing... please wait.")
            start_time = time.time()
            result = trial_division_primitive_test(number)
            end_time = time.time()
            elapsed_time = end_time - start_time

            clear_console()

            if result:
                print(f"The number {number} is Prime")
            else:
                print(f"The number {number} is Composite")

            print(f"The program took {elapsed_time:.6f} seconds to complete.")

        print("(R) to do primality test again")
        print("(M) to return to main menu.")

        choice = wait_for_right_input_receiver("r", "m")

        if choice == "r":
            continue
        elif choice == "m":
            break


def generating_a_pair_of_RSA_keys_flow() -> None:
    clear_console()

    print("How many digits of primes do you want to generate? (more digits mea\
ns more secure keys, but slower generation) (do not input value more than 1000\
, python might crash): ", end="")

    digits = int(input())

    clear_console()

    print("Generating... please wait.")

    prime_1 = generating_prime(digits)
    prime_2 = generating_prime(digits)

    clear_console()

    if digits >= 12:
        confidence = (1 - (pow(1/4, 20) * (2 - pow(1/4, 20)))) * 100  # in %

        # To P'Ve or P'Dew reading my code
        # I double check the confidence level
        # No need to check again. It's just P(not prime) = (1/4)**k
        # And P(at least 1 out of 2 is not prime) is just
        # P(not prime) + P(not prime) - (P(not prime))**2
        # which is what I write above before turn it into percentage

        print(f"Generated primes keys with {confidence}% confidence that b\
oth is prime:\np = {prime_1}\nq = {prime_2}")

    else:
        print(f"Generated primes keys:\np = {prime_1}\nq = {prime_2}")
    modulus = prime_1*prime_2
    public_exponent = public_exponent_generator(
        semiprime_euler_totient(prime_1, prime_2))
    private_exponent = private_exponent_finder(public_exponent,
                                               prime_1,
                                               prime_2)

    if private_exponent == 0:
        print("Cannot find keys, this might due to n not being semiprime \
number\nPlease try again\nPress any key to go back to menu")
        get_char()
        return None

    print(f"Your modulus (n) is {modulus}\nYour public exponent (e) is \
{public_exponent}\nYour private exponent (d) is {private_exponent}")

    print("Press any key to return to main menu.")
    get_char()


def encrypting_a_massage_flow() -> None:
    clear_console()

    print("What is your massage that you want to encrypt?: ")
    massage = input()

    clear_console()

    print("Do you have a public key? (e and n) (Y/N)\nExplaination: let n \
(modulus) be semiprime number, n = p*q.\nϕ(x) is Euler's totient function\nϕ(n\
) = (p-1)*(q-1)\ne (public exponent) is a number we choose such that e is copr\
ime with ϕ(n)\n\nPlease use n greater than 1,200,000 (if it's lower it might c\
ause decryption problem and error)")

    choice = wait_for_right_input_receiver("y", "n")

    clear_console()

    if choice == "y":
        print("Please input your public key (in positive integer of course\
) with n > 1200000 and n must be semiprime, also e must be coprime with ϕ(n)")
        public_exponent = int(input("e (public exponent) = "))
        modulus = int(input("n (modulus) = "))

        if public_exponent >= modulus:
            clear_console()
            print("Your input is wrong\nPress any key to go back to menu")
            get_char()
            return None

    else:
        print("How many digits of prime (p and q) that you will use for en\
cryption? (in integers and please use more than 4, or it might cause error\
when decryption): ", end="")
        digits = int(float(input()))

        prime_1 = generating_prime(digits)
        prime_2 = generating_prime(digits)
        modulus = prime_1 * prime_2

        euler_totient_n = semiprime_euler_totient(prime_1, prime_2)

        public_exponent = public_exponent_generator(euler_totient_n)

        private_exponent = private_exponent_finder(public_exponent, prime_1,
                                                   prime_2)

        print(f"This is your prime p, prime q, n (modulus), e (public exponent\
) and d (private exponent)\np = {prime_1}\nq = {prime_2}\nn = {modulus}\ne = \
{public_exponent}\nd = {private_exponent}\n\nPress any key to continue")

        get_char()

    clear_console()
    print("Encrypting... please wait")

    encrypt_list = []

    for charactor in massage:
        unicode = ord(charactor)
        encrypt_charactor = RSA_encryption(unicode,
                                           public_exponent,
                                           modulus)
        encrypt_list.append(encrypt_charactor)

    clear_console()

    print("This is your encrypt massage\n")
    print(str(encrypt_list).removeprefix("[").removesuffix("]") + "\n")
    print("Press any key to return to menu")

    get_char()


def decrypting_a_massage_flow() -> None:
    clear_console()
    print("""What is your encrypt massage in 1 line in form of
encrypt character 1, encrypt character 2, encrypt character 3, ...
Your encrypt character MUST be positive integer
Example: 1436, 765482, 81523, 194638""")

    encrypt_massage = \
        [int(encrypt_char) for encrypt_char in input().split(", ")]

    if len(encrypt_massage) == 0:
        print("Your decrypt massage is\n\nPress any key to go back to menu")
        get_char()
        return None

    clear_console()

    print("What is your private key? (in positive integer) (n should not be le\
ss than 1,200,000 or there might problems with decryption)")

    private_exponent = int(input("d (private exponent) = "))

    modulus = int(input("n (modulus) = "))

    clear_console()

    decrypt_massage = []

    for encrypt_char in encrypt_massage:
        decrypt_char = RSA_decryption(encrypt_char, private_exponent, modulus)
        decrypt_massage.append(RSA_decryption(encrypt_char,
                                              private_exponent, modulus))

        # If decrypt_char cannot be convert to character
        if decrypt_char > (0x110000):
            print("You have input the wrong key\nPress any key to go back to m\
enu")
            get_char()
            return None

    print("Your decrypt massage is")

    for character in decrypt_massage:
        print(chr(character), end="")

    print("\nPress any key to continue")

    get_char()


"""
|==============================================
|                 Main function
|==============================================
"""


while True:
    clear_console()
    print("""RSA encryption system menu
press the following keys to select an option:
(1) Checking for primality
(2) Generating a pair of RSA keys
(3) Encrypting a message
(4) Decrypting a message
(Q) Quit program""")

    choice = wait_for_right_input_receiver("1", "2", "3", "4", "q")

    if choice == "1":
        check_for_primality_flow()

    elif choice == "2":
        generating_a_pair_of_RSA_keys_flow()

    elif choice == "3":
        encrypting_a_massage_flow()

    elif choice == "4":
        decrypting_a_massage_flow()

    else:
        break
