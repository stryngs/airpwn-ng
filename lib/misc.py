from scapy.all import *

class Misc(object):
    """Miscellaneous class for experimentation"""

    def __init__(self, args):
        self.verbose = args.v
        if args.e:
            self.expSocket = conf.L2socket(iface = args.i)
        else:
            self.expSocket = False
