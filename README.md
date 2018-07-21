The home of the new and improved version of airpwn... airpwn-ng
==============================================================
<hr>

Overview
---

* We force the target's browser to do what we want
	* Most tools of this type simply listen to what a browser does, and if they get lucky, they get the cookie.
	* What if the user isn't browsing the vulnerable site at the point in time which you are sniffing?
	* Wait, you say I can't force your browser to do something?  I sure can if you have cookies stored...
* Demo video: https://www.youtube.com/watch?v=hiyaUZh-UiU
* Find us on IRC (Freenode) at ##ha

Features
---

- Inject to all visible clients (a.k.a Broadcast Mode)
- Inject on OPEN, WEP and WPA protected networks
- Targeted injection with -t MAC:ADDRESS [MAC:ADDRESS]
- Gather all visible cookies (Broadcast Mode)
- Gather cookies for specific websites (--websites websites_list.txt)
	- In this scenario, airpwn-ng will auto-generate invisible iframes for injection that trigger the request for each website in websites_list.txt
	- [BETA] Can be used with --covert flag that attempts to inject a big iframe with the real requested website along with the generated invisible iframes. If successful, the victim should get no indication of compromise. This is still beta and doesn't work with all websites.
	- [BETA] Airpwn-ng API so you can make your own custom attacks. Examples: https://github.com/ICSec/airpwn-ng/blob/master/work-in-progress/api-examples/

How do we do it?
---
* We inject packets into a pre-existing TCP stream
    * For a more detailed and in-depth explanation as to how this occurs, read the original documentation for airpwn: 
        * http://airpwn.sourceforge.net/Documentation.html


That's cool...  So what can we do with it?
---
- Find a website which uses cookies without the SECURE flag set
- Inject lots of wonderful images just like the original airpwn
- All sorts of fun...

Prerequisites:
---
packetEssentials-1.0.8
pbkdf2-1.3
pycryptodomex-3.4.5
pyDot11-2.0.7
rc4-0.1
scapy 2.4.0

#### Setup:

In the RESOURCEs folder you will find the python modules which have been tested.  As newer versions of the modules come out, sufficient testing must be done before they can be made known as "stable" with pyDot11.  Feel free to use pip or whatever method you would like to get these installed.  If you wish to use the modules locally provided with this git, then an installation would be something like so:
````bash
pip install RESOURCEs/packetEssentials-1.0.8.tar.gz
pip install RESOURCEs/pbkdf2-1.3.tar.gz
pip install RESOURCEs/pyDot11-2.0.7.tar.gz
pip install RESOURCEs/pycryptodomex-3.4.5.tar.gz
pip install RESOURCEs/rc4-0.1.tar.gz
pip install RESOURCEs/scapy-2.4.0.tar.gz

## If you run into issues with the scapy module not being found
## Try this local folder workaround
tar zxf RESOURCEs/scapy-2.4.0.tar.gz
mv scapy-2.4.0/scapy/ .
rm -rf scapy-2.4.0/
````

What else do we need to get started?
---
* Aircrack-ng:
  * http://www.aircrack-ng.org/

How do we use airpwn-ng?
---
* Refer to INFOs/Tutorial for basic attack scenarios
