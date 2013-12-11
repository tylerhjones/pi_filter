class Example(object):
   def __init__(self):
       self.stop = threading.Event()
       self.connection = Connection()
       self.mythread = Thread(target=self.dowork)
       self.mythread.start()     
   def dowork(self):

        while(not self.stop.is_set()):
             try:
                  blockingcall()        
             except CommunicationException:
                  pass
   def terminate():
       self.stop.set()
       self.connection.close()
       self.mythread.join()

# MY NEW THREAD CODE 
# **********************************************************************
class FilterQueue(object):
  def __init__(self):
    self.stop       = threading.Event()
    self.connection = Connection()
    self.q          = nfqueue.queue()
    self.mythread   = Thread(target=self.filter)
    self.mythread.start()

  def filter(self):
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(filter_pkt)
    q.create_queue(0)
    q.try_run()

  def filter_pkt(payload):
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


# filter code from original
# **********************************************************************

# filter functions
def add_url_to_list(url):
  ipaddr = socket.gethostbyname(url)
  blocked_list[ipaddr] = url

def check_if_in_list(ipaddr):
  if ipaddr in blocked_list:
    return True
  return False

#  NFQUEUE SETUP & SCAPY
def filter_pkt(payload):
  data = payload.get_data()
  pkt = IP(data)
  # proto = pkt.proto

  # check if packet destination or source is in block list
  if check_if_in_list(pkt[IP].dst):
    payload.set_verdict(nfqueue.NF_DROP)
  elif check_if_in_list(pkt[IP].src):
    payload.set_verdict(nfqueue.NF_DROP)
  else:
    payload.set_verdict(nfqueue.NF_ACCEPT)

def filter_queue():
  q = nfqueue.queue()
  q.open()
  q.bind(socket.AF_INET)
  q.set_callback(filter_pkt)
  q.create_queue(0)

  try:
    q.try_run()
  except KeyboardInterrupt:
    print "Exiting..."
    q.unbind(socket.AF_INET)
    q.close()
    sys.exit(1)


# filter_queue Thread
fq = threading.Thread(target=filter_queue)
fq.daemon = False
fq.start()


