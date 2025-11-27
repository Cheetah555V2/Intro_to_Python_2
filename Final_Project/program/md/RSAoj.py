import RSAmath as rsam
import primitive_test as pt
import RSAerror as RSAE

class RSAKeyPair:
    
    def __init__(self, p: int = None, q: int = None, n: int = None, e: int = None, d: int = None) -> None:
        '''
        p: prime number (int) [optional]
        q: prime number that's not equal to p (int) [optional]
        n: p*q (int) [optional]
        e: public exponent (int) [optional]
        d: private exponent (int) [optional]
        '''

        if type(p) != int and p != None:
            raise TypeError('p argument is not an integer type')
        if type(q) != int and q != None:
            raise TypeError('q argument is not an integer type')
        if type(n) != int and n != None:
            raise TypeError('n argument is not an integer type')
        if type(e) != int and e != None:
            raise TypeError('e argument is not an integer type')
        if type(d) != int and d != None:
            raise TypeError('d argument is not an integer type')
        
        if type(p) == int and not pt.is_prime(p, 64):
            raise RSAE.RSAError('p argument is not prime number')
        if type(q) == int and not pt.is_prime(q, 64):
            raise RSAE.RSAError('q argument is not prime number')
        
        self._p = p
        self._q = q if p != q else None
        self.n = n
        self.e = e
        self._d = d

    def generate_keys(self, digits: int = 310) -> None:
        if self.n != None and self._p != None and self._q == None: # Have n and p but not q
            self._q = self.n // self._p
        if self.n != None and self._q != None and self._p == None: # Have n and q but not p
            self._p = self.n // self._q
        if self._p == None: # Don't have p
            self._p = rsam.gen_prime(digits)
        if self._q == None or self._p == self._q: # Don't have q or q == p
            self._q = rsam.gen_prime(digits)
        self.n = self._p * self._q
        totient = (self._p - 1) * (self._q - 1)
        self.e = rsam.public_exponent_generator(totient)
        self._d = rsam.private_exponent_finder(self.e, totient)
    
    def get_public_key(self):
        """Get public key as tuple (e, n)"""
        return (self.e, self.n)

    def get_private_key(self):
        """Get private key as tuple (d, n)"""
        return (self._d, self.n)