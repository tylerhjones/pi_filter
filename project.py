import os,sys,nfqueue,socket,cherrypy,threading,commands
import filter
from multiprocessing import Process
from mako.template import Template
from mako.lookup import TemplateLookup
import logging


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

# these methods assume only one iptable rule exists in each chain
def add_filter_rule():
    os.system("iptables -A FORWARD -i pibridge -j NFQUEUE --queue-num 0")

def remove_filter_rule():
    os.system("iptables -D FORWARD 1")

def add_server_rule():
  os.system("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")

# System setup checks
print "Checking bridge..."
fails, output = commands.getstatusoutput("ifconfig | grep 'pibridge'")
if fails:
	runbridge_setup()

print "Instantiating the Filter..."
filt = filter.Filter(local_ip)


print "Starting filter queue thread..."
try:
  filt.run()
except Exception:
  print "rebooting filter"
  filt.run()

filter_status = True



print "The starting dictionary..."
print filt.blocked_list

cherrypy.config.update({'server.socket_host': local_ip, 
                         'server.socket_port': 80, 
                        }) 

# mako template directory
lookup = TemplateLookup(directories=['views'])

class FilterServ(object):
  @cherrypy.expose
  def index(self):
    return "requested page is blocked"

  def admin(self, status=filter_status):
    tmpl = lookup.get_template("index.html")
    return tmpl.render(block_list=filt.blocked_list)

  def add_block(self, url=None):
    # print "POST recieved -> parameters are ... "
    # print request.body_params
    print "ADDing URL ... "
    filt.add_url_to_list(url)
    tmpl = lookup.get_template("index.html")
    return tmpl.render(block_list=filt.blocked_list)

  add_block.exposed = True

  def toggle(self):
    return None # fill out later, just toggle the iptable rules

  def remove(self, url=None, key=None):
    return None # fill out later

print "Starting cherrypy server..."

try:
	cherrypy.quickstart(FilterServ())
except KeyboardInterrupt:
	print "Exiting..."
	fq.terminate()
	sys.exit(1)





