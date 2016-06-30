
#!/usr/bin/env python

import math
from scapy.all import *
import struct
import requests
import traceback
from datetime import datetime, timezone
from geoposition import Geoposition
from decimal import Decimal


unique_ssid = []
unique_probe = []

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "BellumIncessius.settings")

import django
django.setup()

from BellumIncessius.settings import GEOPOSITION_GOOGLE_MAPS_API_KEY
from wardrive.models import *
from utils import manufacturer


class Dot11Handler(object):

    api_key = GEOPOSITION_GOOGLE_MAPS_API_KEY

    def __init__(self):
        self.mac_parser = manufacturer.MacParser()

        self.radiotap_formats = {"TSFT":"Q", "Flags":"B", "Rate":"B",
                               "Channel":"HH", "FHSS":"BB",
                         "dBm_AntSignal":"b", "dBm_AntNoise":"b",
                               "Lock_Quality":"H", "TX_Attenuation":"H",
                         "dB_TX_Attenuation":"H",
                               "dBm_TX_Power":"b", "Antenna":"B",
                         "dB_AntSignal":"B",
                               "dB_AntNoise":"B", "b14":"H", "b15":"B",
                         "b16":"B", "b17":"B", "b18":"B",
                               "b19":"BBB", "b20":"LHBB", "b21":"HBBBBBH",
                         "b22":"B", "b23":"B",
                               "b24":"B", "b25":"B", "b26":"B", "b27":"B",
                         "b28":"B", "b29":"B",
                         "b30":"B", "Ext":"B"}

    def handle(self, pkt):
        if pkt.haslayer(Dot11):
            self.handle_dot11(pkt)

    def get_position(self):
        # TODO: Get actual position from GPS device
        obj = {}
        obj['latitude'] = 0.00
        obj['longitude'] = 0.00
        return obj

    def get_location(self, mac, rssi):
        obj = {'wifiAccessPoints': [{'macAddress':mac,
                                     'signalStrength':int(rssi)}] }
        r = requests.post('https://www.googleapis.com/geolocation/v1/geolocate?key={}'.format(self.api_key),
                     json=obj)
        return r.json()

    def log(self, msg):
        print('[{}] {}'.format(datetime.now(), msg))

    def handle_dot11_proberesp(self, pkt):
        if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
            return

        bssid = pkt[Dot11].addr3
        p = pkt[Dot11Elt]
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        ssid, channel = None, None
        crypto = set()

        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                ssid = p.info
            elif p.ID == 3:
                channel = ord(p.info)
            elif p.ID == 48:
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload
        if not crypto:
            if 'privacy' in cap:
                crypto.add("WEP")
            else:
                crypto.add("OPN")

        obj = {'ssid': ssid, 'bssid': bssid, 'channel': channel, 'crypto': ' / '.join(crypto), 
               'manufacturer': {'name': self.mac_parser.get_manuf(bssid), 'comment': self.mac_parser.get_comment(bssid)}
              }
        if not obj in unique_ssid:
            rssi = self.handle_dot11_get_rssi(pkt)
            distance = self.handle_dot11_get_ap_distance_by_rssi(rssi)
            unique_ssid.append(obj)
            self.log("NEW AP: {} [{}], channel {}, {}, RSSI {}, Estimated Distance {}m".format(obj['ssid'],
                                                           obj['bssid'],
                                                           obj['channel'],
                                                           obj['crypto'],
                  rssi,
                  distance))
            try:
                now = datetime.now(timezone.utc)
                w = WirelessAccessPoint.objects.filter(ssid=obj['ssid'],
                                               bssid=obj['bssid'])
                if not w:
                    w = WirelessAccessPoint()
                    w.first_detection_time = now
                else:
                    w = w.get()
                w.ssid = obj['ssid']
                w.bssid = obj['bssid']
                w.crypto = obj['crypto']
                w.last_detection_time = now
                w.save()

                wh = WirelessAccessPointHistory()
                wh.access_point = w
                wh.detection_time = now
                wh.rssi = rssi
                wh.estimated_distance = distance
                pos = self.get_position()
                wh.position = Geoposition(latitude=pos['latitude'],
                                          longitude=pos['longitude'])
                wh.height = 0
                wh.save()
            except:
                traceback.print_exc()



    def handle_dot11_get_rssi(self, pkt):
        field, val = pkt.getfield_and_val("present")
        names = [field.names[i][0] for i in range(len(field.names)) if
                 (1 << i) & val != 0]
        if "dBm_AntSignal" in names:
            fmt = "<"
            rssipos = 0
            for name in names:
                if name == "dBm_AntSignal":
                    rssipos = len(fmt)-1
                fmt = fmt + self.radiotap_formats[name]
            decoded = struct.unpack(fmt,
                                    pkt.notdecoded[:struct.calcsize(fmt)])
        return decoded[rssipos]

    def handle_dot11_get_ap_distance_by_rssi(self, rssi):
        exp = (27.55 - (20 * math.log(2400, 10)) +
                    abs(rssi)) / 20.0;
        distance = math.pow(10.0, exp)
        return '{:3.3f}'.format(distance)

    def handle_dot11_probereq(self, pkt):
        if pkt.type == 0 and pkt.subtype == 4:
            mac = pkt.addr2
            obj = {'ssid': pkt.info, 'mac_address': pkt.addr2, 'manufacturer':
                   {'name': self.mac_parser.get_manuf(mac), 'comment':
                    self.mac_parser.get_comment(mac) }}
            if obj not in unique_probe and len(pkt.info) > 0:

                rssi = self.handle_dot11_get_rssi(pkt)

                unique_probe.append(obj)
                try:
                    vendor = self.mac_parser.get_all(obj['mac_address'])
                except:
                    vendor = "unknown"
                #ap_location = self.get_location(obj['mac_address'], rssi)
                rssi = self.handle_dot11_get_rssi(pkt)
                distance = self.handle_dot11_get_ap_distance_by_rssi(rssi)
                self.log('NEW PROBE: {} ({} {}), RSSI {}, Estimated Distance {}m'.format(obj['ssid'], obj['mac_address'],
                                          obj['manufacturer'], rssi, distance))
                now = datetime.now(timezone.utc)
                w = WirelessAccessPoint.objects.filter(ssid=obj['ssid'])
                if not w:
                    w = WirelessAccessPoint()
                    w.ssid = obj['ssid']
                    w.bssid = 'ff:ff:ff:ff:ff:ff'
                    w.first_detection_time = now
                    w.first_detection_method = 'PROBE'
                    w.last_detection_time = now
                    w.last_detection_method = 'PROBE'
                    w.security = 'UNKNOWN'
                    w.save()
                else:
                    w = w.get()


                c = WirelessClient.objects.filter(mac_address=obj['mac_address'])

                if not c:
                    c = WirelessClient()
                    c.mac_address = obj['mac_address']
                    c.first_detection = now
                    c.last_detection = now
                    c.save()
                else:
                    c = c.get()

                ch = WirelessClientHistory()
                ch.client = c
                ch.detection_time = now
                ch.rssi = rssi
                ch.estimated_distance = distance
                ch.height = 0
                pos = self.get_position()
                ch.position = Geoposition(latitude=pos['latitude'],
                                          longitude=pos['longitude'])
                ch.save()

                wph = WirelessProbeHistory()
                wph.probe_time = now
                wph.ssid = obj['ssid']
                wph.client = c
                wph.save()




    def handle_dot11(self, pkt):
        if pkt.haslayer(Dot11):
            try:
                if Dot11Beacon in pkt or Dot11ProbeResp in pkt:
                    self.handle_dot11_proberesp(pkt)
                if Dot11ProbeReq in pkt:
                    self.handle_dot11_probereq(pkt)

            except AttributeError:
                pass


