The home of the new and improved version of airpwn... airpwn-ng
===============================================================
<hr>

Overview
---

- We force the target's browser to do what we want
	- Most tools of this type simply listen to what a browser does, and if they get lucky, they get the cookie.
	- What if the user isn't browsing the vulnerable site at the point in time which you are sniffing?
	- Wait, you say I can't force your browser to do something?  I sure can if you have cookies stored...


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
- Aircrack-ng:
 - http://www.aircrack-ng.org/
- inotify-tools:
 - https://github.com/rvoicilas/inotify-tools/wiki
- packit:
 - http://packetfactory.openwall.net/projects/packit/
- libpcap
- tcpdump

How do we use airpwn-ng?
---
- Refer to the Tutorial file for a basic example


