# airpwn-ng
This is now the home for the new and "somewhat" improved version of airpwn... airpwn-ng!
----------------------------------------------------------------------------------------

airpwn-ng was born out of the need to create a program that would leverage a commonly known vulnerability that still exists in 2015, cookies without the SECURE flag set.  What!?!  Yes, that's right.  Major websites still lack the most basic of security when it boils down to it.  How to fix?  Release code to the community and let it sort itself out.  There are tons of ways to leverage this, but every one I have encountered is very passive or requires a Man in the Middle type scenario.  Enter, airpwn-ng and how it works.

Well, I guess how it is different might be in order first.  What is airpwn-ng and why should you use it?
	- We force the target's browser to do what we want
		- Most tools of this type simply listen to what a browser does, and if they get lucky, they get the cookie.
		- What if the user isn't browsing the vulnerable site at the point in time which you are sniffing?
		- Wait, you say I can't force your browser to do something?  I sure can if you have cookies stored...

How do we do it?
	- We inject packets into a pre-existing TCP stream
		- For a more detailed and in-depth explanation as to how this occurs, read the original documentation for airpwn: http://airpwn.sourceforge.net/Documentation.html

That's cool...  So what can we do with it?
	- Find a website which uses cookies without the SECURE flag set
	- Inject lots of wonderful images just like the original airpwn
	- All sorts of fun...

What do we need to get started?
	- inotify-tools: https://github.com/rvoicilas/inotify-tools/wiki
	- packit: http://tcpdiag.dl.sourceforge.net/project/packit/packit/0.6.0/packit-0.6.0.tgz
		- Of note: There is a new version out, I have no idea if this is stable with airpwn-ng or not...
			- http://packetfactory.openwall.net/projects/packit/
	- libpcap
	- TWO wifi cards, one in managed mode and one in monitor mode
		- Once I lockdown how to inject in monitor mode properly, this will evolve into only a one card program
	- tcpdump

Okay, so we have all of that, how do we use airpwn-ng?
	- First up we need to figure out what we want to inject.  You can inject whatever you want, and so long as you beat the race condition the browser "should" render it.
	- Once you have figured out what you want to inject, paste it to a file.  Got that done?  Ok, now put a newline on the first line.  It should look something like this:
		- Start of File:
		
		<div style="position:absolute;top:-9999px;left:-9999px;visibility:collapse;">
			<iframe src="http://www.site.com"></iframe>
		</div>
	- Failure to add a new line at the top of the file will result in failures and weird browser rendering from the target perspective.
	- Ok, so now we have our inject file.  Go ahead and join one of your NICs to an open wifi access point
	- Once you have joined the AP, notate the channel for that AP.
	- Using the channel for the managed mode NIC, set your 2nd WiFi NIC (This will be the one in monitor mode) to that channel.
	- Ok, so at this point, you should have one NIC joined to a network, and the other NIC listening on the same channel
	- Run the following:
		- ./airpwn-ng <Inject File> <Sniff NIC> <Inject NIC> <Index Value>
			- When you run it for the first time, you will get a small error due to the fact that the logfile has not been created yet, disregard this warning.
			- To obtain the Index Value, run card-detect!

Well, that just about wraps things up.  Hopefully the community finds this a useful tool.  Enjoy!
Please refer to ToDo.lst if you have any questions regarding this script.  I promise, the answer is most likely in there!

---------------


