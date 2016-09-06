from lib.convos import Conversions
from lib.crypto import Crypto
import argparse

class Engine(object):
    """Enable passing around the engine as an object"""
    
    def __init__(self, seed):
        self.seed = seed

        ## Instantiate the Conversions classes
        self.switch = Conversions()

        ## Turn encryption key to list of ASCII decimal
        self.keyBytes = self.switch.char2dec(self.seed)

        ## Instantiate arc4 and pass it the switch object
        self.arc4 = Crypto(Switch = self.switch)
        

    def engine(self, plainText, option):
        """The object to pass around"""
        keyStream = self.arc4.initialize()
        if option == 'encode':
            return self.arc4.run_rc4(keyStream, plainText)
        elif option == 'decode':
            return self.arc4.run_rc4(keyStream, plainText.decode('string_escape'))
