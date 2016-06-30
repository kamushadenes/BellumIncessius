from django.db import models
from macaddress.fields import MACAddressField
from geoposition.fields import GeopositionField

# Create your models here.


class WirelessAccessPoint(models.Model):
    id = models.AutoField(primary_key=True)
    ssid = models.CharField(max_length=200, db_index=True) 
    bssid = MACAddressField(null=True, blank=True, integer=False)
    first_detection_time = models.DateTimeField()
    first_detection_method = models.CharField(max_length=200)
    last_detection_time = models.DateTimeField()
    last_detection_method = models.CharField(max_length=200)
    security = models.CharField(max_length=200)


class WirelessClient(models.Model):
    id = models.AutoField(primary_key=True)
    first_detection = models.DateTimeField()
    last_detection = models.DateTimeField()
    mac_address = MACAddressField(null=True, blank=True, integer=False)

class WirelessClientHistory(models.Model):
    id = models.AutoField(primary_key=True)
    client = models.ForeignKey(WirelessClient)
    detection_time = models.DateTimeField()
    rssi = models.IntegerField()
    estimated_distance = models.FloatField()
    position = GeopositionField()
    height = models.FloatField()


class WirelessAccessPointHistory(models.Model):
    id = models.AutoField(primary_key=True)
    access_point = models.ForeignKey(WirelessAccessPoint)
    detection_time = models.DateTimeField()
    rssi = models.IntegerField()
    estimated_distance = models.FloatField()
    position = GeopositionField()
    height = models.FloatField()

class WirelessProbeHistory(models.Model):
    id = models.AutoField(primary_key=True)
    probe_time = models.DateTimeField()
    ssid = models.CharField(max_length=200, db_index=True)
    client = models.ForeignKey(WirelessClient)


class FTPRequest(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    code = models.IntegerField()
    direction = models.CharField(max_length=200)
    source_address = models.GenericIPAddressField()
    destination_address = models.GenericIPAddressField()
    source_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_mac_address = MACAddressField(null=True, blank=True, integer=False)
    payload = models.TextField()


class FTPCredential(models.Model):
    id = models.AutoField(primary_key=True)
    server_address = models.GenericIPAddressField()
    detection_time = models.DateTimeField()
    username = models.CharField(max_length=200, db_index=True)
    password = models.CharField(max_length=200)


class HTTPRequest(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    status_code = models.IntegerField()
    direction = models.CharField(max_length=200)
    source_address = models.GenericIPAddressField()
    destination_address = models.GenericIPAddressField()
    source_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_mac_address = MACAddressField(null=True, blank=True, integer=False)
    payload = models.TextField()
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    method = models.CharField(max_length=200, db_index=True, null=True,
                              blank=True)
    host = models.CharField(max_length=200, null=True, blank=True,
                            db_index=True)
    path = models.CharField(max_length=200, null=True, blank=True)
    server = models.CharField(max_length=200, null=True, blank=True,
                              db_index=True)
    headers = models.TextField()

class HTTPCredential(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    destination_address = models.GenericIPAddressField()
    host = models.CharField(max_length=200, null=True, blank=True,
                            db_index=True)
    path = models.CharField(max_length=200, null=True, blank=True)
    username = models.CharField(max_length=200, db_index=True)
    password = models.CharField(max_length=200)
    authorization = models.CharField(max_length=200, null=True, blank=True)



class DNSRequest(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    source_address = models.GenericIPAddressField()
    source_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_address = models.GenericIPAddressField()
    opcode = models.CharField(max_length=200)
    qname = models.CharField(max_length=200)
    qtype = models.CharField(max_length=200)
    qclass = models.CharField(max_length=200)

class TelnetRequest(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    source_address = models.GenericIPAddressField()
    source_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_address = models.GenericIPAddressField()
    payload = models.TextField()

class TelnetCredential(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    destination_address = models.GenericIPAddressField()
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)

class TelnetCommand(models.Model):
    id = models.AutoField(primary_key=True)
    detection_time = models.DateTimeField()
    source_address = models.GenericIPAddressField()
    source_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_mac_address = MACAddressField(null=True, blank=True, integer=False)
    destination_address = models.GenericIPAddressField()
    command = models.TextField()
