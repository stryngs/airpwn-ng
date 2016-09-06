class Conversions(object):

    def __init__(self):
        pass


    def char2dec(self, string):
        """Create a list of ASCII decimal
        Obtained via individual characters in string
        """
        self.keyBytes = [ord(char) for char in string]
        return self.keyBytes
        
    
    def char2hex(self, pVals):
        """Takes the str() format of the packet
        Breaks it down per byte (x[i]), and coverts to ASCII hex format
        Appends the ASCII hex format in str() format to the list
        """
        x = str(pVals)
        l = len(pVals)
        hList = []
        for i in range(l):
            #hList.append("%02X" % ord(x[i]))
            hList.append(str(ord(x[i])))
        return hList


    def hex2dec(self, hVals):
        """Takes a list of ASCII hex (string or int format, doesn't matter)
        Converts the ASCII hex format to ASCII decimal format
        """
        #x = str(hVals)
        pList = []
        for i in hVals:
            #pList.append(int('0X' + i, 16))
            pList.append(int(str(i), 16))
        return pList


    def hex2char(self, hVals):
        """Take a list of ASCII hex format
        Converts the ASCII hex format to ASCII char format
        
        This should be the function that let's us convert back into proper scapy format
        """
        #x = str(hVals)
        cList = []
        for i in hVals:
            cList.append(chr(int(i)))
        return cList
