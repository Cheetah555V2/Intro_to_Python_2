class RSAError(Exception):
    pass

class PrimeGenerationError(RSAError):
    pass

class KeyGenerationError(RSAError):
    pass

class EncryptionError(RSAError):
    pass

class DecryptionError(RSAError):
    pass