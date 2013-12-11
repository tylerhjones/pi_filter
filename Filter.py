from multiprocessing import Process
import os,sys,nfqueue,socket,copy
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


conf.verbose  = 0
conf.L3socket = L3RawSocket

class Filter(object):

	def add_url_to_list(self, url):
		ipaddr = socket.gethostbyname(url)
		self.blocked_list[ipaddr] = url
		if "www." not in url:
			ipaddr = socket.gethostbyname("www."+url) # tyler this will crash on things like eu.woot.com
			self.blocked_list[ipaddr] = "www."+url
	
	def check_if_in_list(self, ipaddr):
		if ipaddr in self.blocked_list:
			return True
		return False

	def check_if_in_list(self, ipaddr): 
		if ipaddr in self.blocked_list:    
			return True
		return False

	def filter_pkt(self, payload):
		data = payload.get_data()
		pkt = IP(data)
		# check if packet destination or source is in blocked list
		if self.check_if_in_list(pkt[IP].dst):
		  payload.set_verdict(nfqueue.NF_DROP)
		elif self.check_if_in_list(pkt[IP].src):
		  payload.set_verdict(nfqueue.NF_DROP)
		else:
		  payload.set_verdict(nfqueue.NF_ACCEPT)

	def renew_ip_list(self):
		# tmpdict = copy.deepcopy(self.blocked_list) saved for deepcopy example
		tmpdict = {}
		for key in self.blocked_list:
			url = self.blocked_list[key]
			tmpdict[socket.gethostbyname(url)] = url
		self.blocked_list = copy.deepcopy(tmpdict)

	def go(self):
		self.q = nfqueue.queue()
		self.q.open()
		self.q.bind(socket.AF_INET)
		self.q.set_callback(self.filter_pkt)
		self.q.create_queue(0)
		self.q.try_run()

	def __init__(self):
		self.blocked_list = {'75.101.146.4': "www.woot.com", '75.101.146.4': "woot.com"} #  format of dictionary is  list= {'ipaddress': url}
		# poor woot, getting hated on by default
		self.p = Process(target=self.go)
		self.renew_ip_list() # just call this right off the start
		

	def run(self):
		self.p.start()