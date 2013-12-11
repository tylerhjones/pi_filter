import os,sys,nfqueue,socket,cherrypy,threading,commands
import Filter
from multiprocessing import Process
from mako.template import Template
from mako.lookup import TemplateLookup
import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


conf.verbose  = 0
conf.L3socket = L3RawSocket

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




# System setup checks
print "Checking bridge..."
fails, output = commands.getstatusoutput("ifconfig | grep 'pibridge'")
if fails:
	runbridge_setup()

print "Instantiating the Filter..."
filt = Filter()


print "Starting filter queue thread..."
try:
  filt.start()
except:
  filt.start()

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





