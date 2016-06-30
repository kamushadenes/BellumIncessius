from scapy.all import *
from datetime import datetime, timezone
from wardrive.models import TelnetRequest, TelnetCredential, TelnetCommand

class TelnetHandler(object):

    username_expects = ['login', 'user', 'username']
    password_expects = ['password', 'senha']
    enter_key = '\r\x00'.encode()
    newline = '\r\n'.encode()

    def __init__(self):
        self.current_login = ''
        self.current_password = ''
        self.getting_login = False
        self.getting_password = False

        self.got_credentials = False

        self.current_command = ''
        self.getting_command = False

        self.current_credential = {'username': '', 'password': ''}

        self.skip_feedback = False

    def handle(self, pkt):
        payload = pkt[Raw].load

        try:
            payload.decode()
        except:
            return

        now = datetime.now(timezone.utc)

        tr = TelnetRequest()
        tr.detection_time = now
        tr.source_address = pkt[IP].src
        tr.source_mac_address = pkt[Ether].src
        tr.destination_address = pkt[IP].dst
        tr.destination_mac_address = pkt[Ether].dst
        tr.payload = payload

        tr.save()


        if not self.getting_login and not self.getting_password and not self.getting_command:
            try:
                for ue in self.username_expects:
                    if '{}:'.format(ue).encode().upper() in payload.upper():
                        self.getting_login = True
                        self.current_login = ''

                for pe in self.password_expects:
                    if '{}:'.format(pe).encode().upper() in payload.upper():
                        self.getting_password = True
                        self.current_password = ''

                if not self.getting_login and not self.getting_password:
                    self.getting_command = True
            except AttributeError:
                pass
        else:
            if self.getting_login:
                if self.enter_key in payload:
                    self.getting_login = False
                    self.current_credential['username'] = self.current_login
                else:
                    if self.skip_feedback:
                        self.skip_feedback = False
                    else:
                        self.current_login = '{}{}'.format(self.current_login,
                                                       payload.decode())
                        self.skip_feedback = True
            elif self.getting_password:
                if self.enter_key in payload:
                    self.getting_password = False
                    self.current_credential['password'] = self.current_password

                    tc = TelnetCredential()
                    tc.detection_time = now
                    tc.destination_address = pkt[IP].dst
                    tc.username = self.current_credential['username']
                    tc.password = self.current_credential['password']
                    tc.save()

                    self.current_credential = {'username': '', 'password': ''}

                else:
                    self.current_password = '{}{}'.format(self.current_password, payload.decode())

            elif self.getting_command:
                if self.enter_key in payload:
                    # TODO: Improve command parsing
                    self.getting_command = False

                    tcm = TelnetCommand()
                    tcm.detection_time = now
                    tcm.source_address = pkt[IP].src
                    tcm.source_mac_address = pkt[Ether].src
                    tcm.destination_address = pkt[IP].dst
                    tcm.destination_mac_address = pkt[Ether].dst
                    tcm.command = self.current_command.strip().split(self.newline.decode())[-1]
                    tcm.save()

                    self.current_command = ''
                else:
                    if self.skip_feedback:
                        self.skip_feedback = False
                    else:
                        self.current_command = '{}{}'.format(self.current_command,
                                                       payload.decode())
                        self.skip_feedback = True

