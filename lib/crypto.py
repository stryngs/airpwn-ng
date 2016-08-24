import re
from binascii import crc32, hexlify, unhexlify
from rc4 import rc4
from scapy.all import *

class Wep(object):

    def __init__(self):
        pass
    
    
    def seedGen(self, iv, keyText):
        """Simple for now, eventually use logic?"""
        return iv + keyText
    
    
    def deBuilder(self, pkt, stream):
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the encryption layer
        del reflection[Dot11WEP]

        ## Add the LLC layer
        reflection = reflection/LLC()

        ## Create the packet without encryption and return it
        llcStruct = LLC(stream)
        reflection[LLC] = llcStruct
        return reflection


    def decoder(self, pkt, keyText):
        ## We cheat here and re-use the IV later on
        iVal = pkt[Dot11WEP].iv
        seed = self.seedGen(iVal, unhexlify(keyText))
        
        ## Grab full stream
        fullStream = rc4(pkt[Dot11WEP].wepdata, seed)
        
        ## Prep for removing the 4 icv bytes
        smallStream = []
        stream = ''
        for i in range(len(fullStream) - 4):
            smallStream.append(fullStream[i])
        for i in smallStream:
            stream += i
        
        ## Return the fullstream, stream and iv
        return fullStream, stream, iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = crc32(str(pkt[LLC]))
        plainText = str(pkt[LLC])
        
        print 'wepICV is: ', wepICV
        print 'hex of ^ is: ', hex(wepICV)
        print 'unhexlify of ^ is: ', unhexlify(re.sub('0x', '', hex(wepICV)))
        print 'repr of ^ is: ', repr(unhexlify(re.sub('0x', '', hex(wepICV))))
        #stream = plainText + str(wepICV)
        #stream = plainText + hex(wepICV)
        #stream = plainText + unhexlify(re.sub('0x', '', hex(wepICV)))
        stream = plainText
        
        ## crypt
        seed = self.seedGen(iVal, unhexlify(keyText))
        return rc4(stream, seed), wepICV


    def enBuilder(self, pkt, stream, iVal, wepICV):
        ## Mirror the packet
        reflection = pkt.copy()

        ## Remove the LLC layer
        del reflection[LLC]

        ## Add the Dot11WEP layer
        reflection = reflection/Dot11WEP()
        reflection[Dot11WEP].iv = iVal
        reflection[Dot11WEP].keyid = 0
        reflection[Dot11WEP].wepdata = stream
        reflection[Dot11WEP].icv = wepICV

        return reflection
        

class Wpa(object):
    pass

