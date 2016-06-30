#!/usr/bin/env python

from scapy.all import *
import requests
import traceback
from datetime import datetime, timezone


unique_ssid = []
unique_probe = []

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "BellumIncessius.settings")

import django
django.setup()

from scapy_http import http

from wardrive.models import *
from handlers.dot11 import Dot11Handler
from handlers.ftp import FTPHandler
from handlers.http import HTTPHandler
from handlers.dns import DNSHandler
from handlers.telnet import TelnetHandler

class PacketHandler(object):

    def __init__(self):
        self.dot11 = Dot11Handler()
        self.ftp = FTPHandler()
        self.http = HTTPHandler()
        self.dns = DNSHandler()
        self.telnet = TelnetHandler()

    def handle(self, pkt):
        if pkt.haslayer(Dot11):
            self.dot11.handle(pkt)
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                self.ftp.handle(pkt)
            elif pkt.haslayer(http.HTTP) or pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                self.http.handle(pkt)
            elif pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                self.telnet.handle(pkt)
        elif pkt.haslayer(UDP):
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                self.dns.handle(pkt)


handler = PacketHandler()

sniff(iface="wlo1", prn = handler.handle, store=False)
