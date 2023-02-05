#!/usr/bin/env python3
import socket
import urllib.request
import nntplib
from time import ctime
import struct, time
import ssl 


socket.setdefaulttimeout(2)

class Service:
    def __init__(self, ip = '127.0.0.1', tcp=0, udp = 0, icmp = False, app=None):
        self.ip = ip
        self.tcp = tcp
        self.udp = udp
        self.icmp = icmp
        self.app = app
        self.status = False 
        self.test_comment = 'No comment returned from test.'
        self.test()
        self.report_results()
    
    def report_results(self):
        status = 'up' if self.status else 'down'
        print(self.ip, self.tcp, self.udp, self.icmp, self.app, status, self.test_comment)

    def tcp(self):
        pass

    def test(self):
        if self.app:
            self.test_app()
        if self.tcp:
            self.test_tcp()
        elif self.icmp:
            self.test_icmp()

    def test_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((self.ip,self.tcp))
            if result ==0:
                self.status = True
            s.close()
    
    def test_icmp(self):
        print('pinging', self.ip)
        return 

    def udp(self):
        pass

    def icmp(self):
        pass 

    def test_app(self):
        if 'http' in self.app: 
            self.status = self.http_app()
        elif 'ntp' in self.app:
            self.status = self.ntp_app()

    def http_app(self):
        url = f'{self.app}://{self.ip}'    
        ssl._create_default_https_context = ssl._create_unverified_context
        try: 
            with urllib.request.urlopen(url) as response:
                if response.code == 200:
                    return True 
                else:
                    self.test_comment = 'Did not receive response code = 200'
                    return False 
        except: 
            self.test_comment = 'Did not receive response code = 200'
            return False 


    def ntp_app(self):
        port = 123
        buf = 1024
        address = (self.ip,port)
        msg = '\x1b' + 47 * '\0'
        # reference time (in seconds since 1900-01-01 00:00:00)
        TIME1970 = 2208988800 # 1970-01-01 00:00:00
 
        try: 
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(msg.encode('utf-8'), address)
                msg, address = client.recvfrom( buf )
                t = struct.unpack( "!12I", msg )[10]
                t -= TIME1970
                self.test_comment = 'Time returned from NTP server: ' + time.ctime(t).replace("  "," ")
                return True 
        except:
            self.test_comment = 'Server NTP query failed.'
            return False 


print('host, tcp port, udp port, icmp, application, up|down')
web = Service(ip='www.google.com', tcp=99)
web = Service(ip='www.google.com', tcp=80)
web = Service(ip='www.google.com', tcp=443)
web = Service(ip='www.amazon.com', tcp=443)
web = Service(ip='www.yournetguard.com', tcp=22)
web = Service(ip='127.0.0.1', app='http')
web = Service(ip='www.cnn.com', app='https')
web = Service(ip='www.google.com', icmp=True)
web = Service(ip='pool.ntp.org', app='ntp')
web = Service(ip='www.google.com', app='ntp')



