
class Filter(object):

	def add_url_to_list(self, url):
		ipaddr = socket.gethostbyname(url)
		self.blocked_list[ipaddr] = url

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
		pkt  = IP(data)
		# check if packet destination or source is in block list
		if check_if_in_list(pkt[IP].dst):
		  payload.set_verdict(nfqueue.NF_DROP)
		elif check_if_in_list(pkt[IP].src):
		  payload.set_verdict(nfqueue.NF_DROP)
		else:
		  payload.set_verdict(nfqueue.NF_ACCEPT)

	def go(self):
		self.q = nfqueue.queue()
		self.q.open()
		self.q.bind(socket.AF_INET)
		self.q.set_callback(self.filter_pkt)
		self.q.create_queue(0)
		self.q.try_run()

	def _init_(self):
		self.blocked_list = {'75.101.146.4': "woot.com"} #  format of dictionary is  list= {'ipaddress': url}
		self.p = Process(target=go)
		# poor woot, getting hated on by default

	def run(self):
		self.p.start()