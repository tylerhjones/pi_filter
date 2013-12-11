import os,sys,nfqueue,socket,cherrypy,threading,commands
from mako.template import Template
from mako.lookup import TemplateLookup
import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


conf.verbose  = 0
conf.L3socket = L3RawSocket


# global variables
blocked_list   = {'75.101.146.4': "woot.com"} #  format of dictionary is  list= {'ipaddress': url}
filter_running = True
if len(sys.argv) > 1:
	local_ip   = str(sys.argv[1]) # first arg taken is the local ip on eth0
else:
	local_ip   = '192.168.0.80' # default local ip and the ip the device often gets at home


# the failure value and the output is captured in case more 'intelligence' is added later
def runbridge_setup():
	fails, output = commands.getstatusoutput("brctl addbr pibridge")
	if fails:
		print "Error with brctl: " + str(output)
		sys.exit(1)
	fails, output = commands.getstatusoutput("brctl addif pibridge eth1")
	if fails:
		print "Error with brctl: " + str(output)
		sys.exit(1)
	fails, output = commands.getstatusoutput("brctl addif pibridge eth2")
	if fails:
		print "Error with brctl: " + str(output)
		sys.exit(1)

# these methods assume only one iptable rule exists
def add_iptables_rule():
    os.system("iptables -A FORWARD -i pibridge -j NFQUEUE --queue-num 0")

def remove_iptables_rule():
    os.system("iptables -D FORWARD 1")

# filter functions
def add_url_to_list(url):
	ipaddr = socket.gethostbyname(url)
	blocked_list[ipaddr] = url

def check_if_in_list(ipaddr):
	if ipaddr in blocked_list:
		return True
	return False

def check_if_in_list(ipaddr):
    if ipaddr in blocked_list:
	    return True
    return False

class FilterQueue(object):
  def __init__(self):
    threading.Thread(self.run(self))
    # self.mythread.start()

  def run(dummy, self):
    self.q = nfqueue.queue()
    self.q.open()
    self.q.bind(socket.AF_INET)
    self.q.set_callback(self.filter_pkt)
    self.q.create_queue(0)
    self.q.try_run()

  def filter_pkt(dummy, payload):
    data = payload.get_data()
    pkt  = IP(data)
    # check if packet destination or source is in block list
    if check_if_in_list(pkt[IP].dst):
      payload.set_verdict(nfqueue.NF_DROP)
    elif check_if_in_list(pkt[IP].src):
      payload.set_verdict(nfqueue.NF_DROP)
    else:
      payload.set_verdict(nfqueue.NF_ACCEPT)

  def terminate():
    self.q.unbind(socket.AF_INET)
    self.q.close()
    self.mythread.join()


# System setup checks
fails, output = commands.getstatusoutput("ifconfig | grep 'pibridge'")
if fails:
	runbridge_setup()

print "Instantiating the FilterQueue..."
fq = FilterQueue()
print "Starting filter queue thread..."
fq.start()

cherrypy.config.update({'server.socket_host': local_ip, 
                         'server.socket_port': 80, 
                        })

# mako template directory
lookup = TemplateLookup(directories=['views'])

class FilterServ(object):
	@cherrypy.expose
	def index(self):
		tmpl = lookup.get_template("index.html")
		return tmpl.render(block_list=blocked_list)

print "Starting cherrypy server..."

try:
	cherrypy.quickstart(FilterServ())
except KeyboardInterrupt:
	print "Exiting..."
	fq.terminate()
	sys.exit(1)





