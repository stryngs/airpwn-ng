from scapy.all import *

class Misc(object):
    """Miscellaneous class for experimentation
    
    Used to test specific theories revolving around
    what injection can or cannot do.

    The resultant object might potentially waste cycles
    """

    def __init__(self, args):
        ## Experimental sockets
        if args.e:
            self.expSocket = conf.L2socket(iface = args.i)
        else:
            self.expSocket = False

        ## Single packets
        self.single = args.single

        ## Verbosity
        self.verbose = args.v