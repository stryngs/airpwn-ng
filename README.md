The home of the new and improved version of airpwn... airpwn-ng
===============================================================
<hr>

Overview
---

- We force the target's browser to do what we want
	- Most tools of this type simply listen to what a browser does, and if they get lucky, they get the cookie.
	- What if the user isn't browsing the vulnerable site at the point in time which you are sniffing?
	- Wait, you say I can't force your browser to do something?  I sure can if you have cookies stored...

Features
---

- Inject to all visible clients (a.k.a Broadcast Mode)
- Inject on both open networks and WEP/WPA protected networks
- Targeted injection with -t MAC:ADDRESS [MAC:ADDRESS]
- Gather all visible cookies (Broadcast Mode)
- Gather cookies for specific websites (--websites websites_list.txt)
	- In this scenario, airpwn-ng will auto-generate invisible iframes for injection that trigger the request for each website in websites_list.txt
	- [BETA] Can be used with --covert flag that attempts to inject a big iframe with the real requested website along with the generated invisible iframes. If successful, the victim should get no indication of compromise. This is still beta and doesn't work with all websites.
	- [BETA] Airpwn-ng API so you can make your own custom attacks. Examples: https://github.com/stryngs/airpwn-ng/blob/master/work-in-progress/api-examples/

How do we do it?
---
- We inject packets into a pre-existing TCP stream
	- For a more detailed and in-depth explanation as to how this occurs, read the original documentation for airpwn: http://airpwn.sourceforge.net/Documentation.html


That's cool...  So what can we do with it?
---
- Find a website which uses cookies without the SECURE flag set
- Inject lots of wonderful images just like the original airpwn
- All sorts of fun...


What do we need to get started?
---
- scapy:
 - http://www.secdev.org/projects/scapy/
- Aircrack-ng:
 - http://www.aircrack-ng.org/
- libpcap
- dot11decrypt (For WEP/WPA decryption):
 - https://github.com/mfontanini/dot11decrypt

How do we use airpwn-ng?
---
- Refer to the Tutorial file for a basic attack scenario

Example Syntax
---
- Open networks:

`./airpwn-ng -m mon0 -i mon0 --injection testinject`
- WEP/WPA protected networks:

`./airpwn-ng -m tap0 -i wlan0 --websites websites.txt`
