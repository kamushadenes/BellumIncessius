from scapy.all import *
from wardrive.models import DNSRequest
from datetime import datetime, timezone

class DNSHandler(object):

    dnstypes = { 0:"ANY", 255:"ALL",
                         1:"A", 2:"NS", 3:"MD", 4:"MF", 5:"CNAME", 6:"SOA", 7:
            "MB", 8:"MG",
                         9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
                         17:"RP",18:"AFSDB",28:"AAAA",
            33:"SRV",38:"A6",39:"DNAME",
                         41:"OPT", 43:"DS", 46:"RRSIG", 47:"NSEC", 48:"DNSKEY",
                     50: "NSEC3", 51: "NSEC3PARAM", 32769:"DLV" }

    dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
    dnsqtypes.update(dnstypes)
    dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}

    def __init__(self):
        pass

    def handle(self, pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            now = datetime.now(timezone.utc)

            dr = DNSRequest()
            dr.detection_time = now
            dr.source_address = pkt[IP].src
            dr.destination_address = pkt[IP].dst
            dr.source_mac_address = pkt[Ether].src
            dr.destination_mac_address = pkt[Ether].dst

            dr.opcode = pkt[DNS].opcode
            dr.qname = pkt[DNS].qd.qname
            dr.qtype = self.dnsqtypes.get(pkt[DNS].qd.qtype, pkt[DNS].qd.qtype)
            dr.qclass = self.dnsclasses.get(pkt[DNS].qd.qclass, pkt[DNS].qd.qclass)

            dr.save()
