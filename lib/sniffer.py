from Queue import Queue, Empty
from threading import Thread
from scapy.all import *
import binascii, fcntl, gzip, socket, struct, sys, time
from lib.injector import *

class Sniffer:
	'''This is the highest level object in the library.
	
	It uses an instance of PacketHandler as the processing engine for packets received from scapy's sniff() function.
	'''

	def __init__(self,packethandler, *positional_parameters, **keyword_parameters):
		if ('filter' in keyword_parameters):
                        self.filter = keyword_parameters['filter']
		else:
			self.filter = None

		if ('m' in keyword_parameters):
                        self.m = keyword_parameters['m']
		else:
			self.m = None

		if (self.m is None):
			print "[ERROR] No monitor interface selected"
			exit()

		if (self.filter is None):
			if ("mon" not in self.m):
				print "[WARN] SNIFFER: Filter empty for non-monitor interface"

		self.packethandler = packethandler


	def sniff(self, q):
		'''Target function for Queue (multithreading).
		
		Usually we set a filter for GET requests on the dot11 tap interface.
		It can also be an empty string.
		'''
		if ("mon" in self.m):
			sniff(iface = self.m, prn = lambda x : q.put(x), store=0)
		else:
			sniff(iface = self.m, filter = self.filter, prn = lambda x : q.put(x), store=0)


	def threaded_sniff(self, single = False):
		'''This starts a Queue which receives packets and processes them.
		
		It uses the PacketHandler.process function.
		Call this function to begin actual sniffing + injection. 
		'''
		q = Queue()
		sniffer = Thread(target = self.sniff, args = (q,))
		sniffer.daemon = True
		sniffer.start()
		while True:
			try:
				pkt = q.get(timeout = 1)
				self.packethandler.process(self.m, pkt, single)
				q.task_done()
			except Empty:
				#q.task_done()
				pass