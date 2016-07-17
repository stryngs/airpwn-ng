from lib.parameters import VictimParameters
from lib.packet_handler import PacketHandler
from lib.sniffer import Sniffer

class Web(object):
    """
    This sets up VictimParameters, PacketHandler and the Victims (if any...).

    It uses the library classes and functions according to what arguments are provided.
    """

    def style_web(self, args, websites, i_iface, m_iface, expSocket):
        """Handle Website Lists"""
        if args.covert:
            vp = VictimParameters(websites = websites, covert = args.covert)
        else:
            vp = VictimParameters(websites = websites)

        ## Broadcast mode
        if not args.t:
            if (args.exclude_hosts is None):
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victim_parameters = vp)
            else:
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victim_parameters = vp, excluded = args.exclude_hosts)

        ## Targeted mode
        else:
            victims = []
            for victim in args.t:
                v1 = Victim(mac = victim, victim_parameters = vp)
                victims.append(v1)

            if (args.exclude_hosts is None):
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victims = victims)
            else:
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victims = victims, excluded = args.exclude_hosts)

        if ("mon" in m_iface):
            snif = Sniffer(ph, m = m_iface)
            snif.threaded_sniff(args)
        else:
            snif = Sniffer(ph, m = m_iface, filter = '')
            snif.threaded_sniff(args)



class Inject(object):
    """
    This sets up VictimParameters, PacketHandler and the Victims (if any...).

    It uses the library classes and functions according to what arguments are provided.
    """

    def style_inject(self, args, i_iface, m_iface, expSocket):
        """Handle injection without a targeted domain list"""
        ## Handle victim parameters
        if args.covert:
            ## Broadcast mode
            if not args.t:
                vp = VictimParameters(inject_file = args.injection, covert = args.covert, highjack = highjacker)
            ## Targeted mode
            else:
                vp = VictimParameters(inject_file = args.injection, covert = args.covert)
        else:
            vp = VictimParameters(inject_file = args.injection)

        ## Broadcast mode
        if not args.t:
            if (args.exclude_hosts is None):
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victim_parameters = vp)
            else:
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victim_parameters = vp, excluded = args.exclude_hosts)

        ## Targeted mode
        else:
            victims = []
            for victim in args.t:
                v1 = Victim(mac = victim, victim_parameters = vp)
                victims.append(v1)

            if (args.exclude_hosts is None):
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victims = victims)
            else:
                ph = PacketHandler(expSocket, i = i_iface, exp = args.e, victims = victims, excluded = args.exclude_hosts)

        ## Single packet injection logic
        if args.single:
            if "mon" in m_iface:
                snif = Sniffer(ph, m = m_iface)
                snif.threaded_sniff(args, True)
            else:
                ## Broadcast mode
                if not args.t:
                    snif = Sniffer(ph, m = m_face, filter = '')

                ## Targeted mode
                else:
                    snif = Sniffer(ph, m = m_iface)

                snif.threaded_sniff(args, True)
        else:
            if ("mon" in m_iface):
                snif = Sniffer(ph, m = m_iface)
                snif.threaded_sniff(args)
            else:
                ## Broadcast mode
                if not args.t:
                    snif = Sniffer(ph, m = m_iface, filter = '')

                ## Targeted mode
                else:
                    snif = Sniffer(ph, m = m_iface)

                snif.threaded_sniff(args)
