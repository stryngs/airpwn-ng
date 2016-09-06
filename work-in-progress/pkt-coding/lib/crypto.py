import binascii

class Crypto(object):
    
    def __init__(self, **kwargs):
        if 'Switch' in kwargs:
            self.switch = kwargs['Switch']
    
    
    def initialize(self):
        """Produce a 256-entry list
        This is the first step in RC4
        """
        keyStream = range(256)
        j = 0
        jList = []
        
        for i in range(256):
            j = (j + keyStream[i] + self.switch.keyBytes[i % len(self.switch.keyBytes)]) % 256
            keyStream[i], keyStream[j] = keyStream[j], keyStream[i]
        self.keyStream = keyStream
        return keyStream


    def gen_random_bytes(self, k):
        """Yield a pseudo-random stream of bytes based on 256-byte array `k`."""
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + k[i]) % 256
            k[i], k[j] = k[j], k[i]
            yield k[(k[i] + k[j]) % 256]    


    def run_rc4(self, k, text):
        cipher_chars = []
        random_byte_gen = self.gen_random_bytes(k)
        for char in text:
            byte = ord(char)
            cipher_byte = byte ^ random_byte_gen.next()
            cipher_chars.append(chr(cipher_byte))
        return cipher_chars
    
    
