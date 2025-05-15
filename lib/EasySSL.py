#!/usr/bin/python
# MIT License
# 
# Copyright (c) 2025 Evan Custodio & TheZakMan
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import socket, ssl
import time
from urllib.parse import urlparse

# EasySSL: A simple module to perform SSL Queries
class EasySSL():
	# constructor: we can specify recv bufsize
	def __init__(self, SSLFlag=True, bufsize=8192, proxy=None):
		self.bufsize = bufsize
		self.SSLFlag = SSLFlag
		self.proxy = proxy
		
	# parse_proxy - Parse proxy URL into components
	def parse_proxy(self):
		if self.proxy is None:
			return None
			
		proxy_parsed = urlparse(self.proxy)
		proxy_host = proxy_parsed.hostname
		proxy_port = proxy_parsed.port or 8080  # Default to 8080 if no port specified
		
		return (proxy_host, proxy_port)
		
	# connect_via_proxy - Connect to destination through proxy
	def connect_via_proxy(self, host, port, timeout=None):
		proxy_info = self.parse_proxy()
		if not proxy_info:
			return False
			
		proxy_host, proxy_port = proxy_info
		
		# Create socket and connect to proxy
		self.s = socket.create_connection((proxy_host, proxy_port), timeout)
		
		if self.SSLFlag:
			# For HTTPS, use HTTP CONNECT method to establish tunnel
			connect_str = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
			self.s.sendall(connect_str.encode())
			
			# Read proxy response
			response = b""
			while b"\r\n\r\n" not in response:
				chunk = self.s.recv(4096)
				if not chunk:
					break
				response += chunk
			
			# Check if connection established
			if b"200 Connection established" not in response:
				self.s.close()
				raise Exception(f"Proxy connection failed: {response.decode('utf-8', 'ignore')}")
				
			# Wrap socket with SSL
			self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
			self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
			self.ssl.settimeout(timeout)
		
		return True
		
	# connect() - Simply provide webserver address and optional port (default 443)
	def connect(self, host, port=443, timeout=None):
		# Use proxy if specified
		if self.proxy:
			if self.connect_via_proxy(host, port, timeout):
				return
		
		# Direct connection (no proxy)
		if self.SSLFlag:
			self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
			self.s = socket.setdefaulttimeout(timeout)
			self.s = socket.create_connection((host, port))
			self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
			self.ssl.settimeout(timeout)
		else:
			self.s = socket.setdefaulttimeout(timeout)
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.s.settimeout(timeout)
			self.s.connect((host, port))

			
	def close(self):
		if (self.SSLFlag):
			self.ssl.close()
			del self.ssl
			del self.context
			del self.s
		else:
			self.s.close()
			del self.s
		
	# send() - Sends data through the socket
	def send(self, data):
		if (self.SSLFlag):
			return self.ssl.send(data)
		else:
			return self.s.send(data)
		
	def recv(self):
		try:
			if (self.SSLFlag):
				self.ssl.settimeout(None)
				buffer = self.ssl.recv(self.bufsize)
			else:
				self.s.settimeout(None)
				buffer = self.s.recv(self.bufsize)

		except Exception as e:
			buffer = None
			#print (e)
		return buffer
		
	def recv_nb(self,timeout=0.0):
		try:
			
			if (self.SSLFlag):
				self.ssl.settimeout(timeout)
				buffer = self.ssl.recv(self.bufsize)
			else:
				self.s.settimeout(timeout)
				buffer = self.s.recv(self.bufsize)

		except Exception as e:
			buffer = None
			#print (e)
		return buffer

	# recv_web is an HTTP response parser. This parser has been hacked together and probably doesn't conform to RFC
	# please do not use this for any serious HTTP response parsing. Only meant for security research
	def recv_web(self):
		ST_PROCESS_HEADERS = 0
		ST_PROCESS_BODY_CL = 1
		ST_PROCESS_BODY_TE = 2
		ST_PROCESS_BODY_NODATA = 3
	
		state = ST_PROCESS_HEADERS
		dat_raw = b""
		CL_TE = -1
		size = 0
		k = 0
		cls = False
		http_ver = "1.1" # assume 1.1, this will get overwritten
		while(1):
			#time.sleep(0.01)
			#k += 1
			#print ("loop %d" %(k))
			#print ("state = %d"%(state))
			retry = 0
			while (1):
				
				sample = self.recv_nb(1)
				if ((sample == None) or (sample == b"")):
					if (retry == 5):
						if len(dat_raw) == 0:
							cls = True
						return (cls, dat_raw.decode("UTF-8",'ignore'))
					retry += 1
				else:
					dat_raw += sample
					break
					
			dat_dec = dat_raw.decode("UTF-8",'ignore')
			dat_split = dat_dec.split("\r\n")
			
			if (state == ST_PROCESS_HEADERS):
				if dat_split[0][0:4] == "HTTP":
					#print("Found HTTP")
					http_ver = dat_split[0][5:8]
					if (http_ver == "1.0"):
						cls = True
					state = ST_PROCESS_HEADERS
					for line in dat_split:
						if (len(line) >= len("Transfer-Encoding:")) and (line[0:18].lower() == "transfer-encoding:"):
							#print ("Found TE Header")
							CL_TE = 1
						elif (len(line) >= len("Content-Length:")) and (line[0:15].lower() == "content-length:"):
							size = int(line[15:].strip())
							#print ("Found CL Header: Size %d" % (size))
							CL_TE = 0
						elif (len(line) >= len("Connection: close")) and (line[0:17].lower() == "connection: close"):
							cls = True
						elif (len(line) >= len("Connection: keep-alive")) and (line[0:22] == "connection: keep-alive"):
							cls = False
						elif (line == ""):
							#print ("Found end of headers")
							if (CL_TE == 0):
								state = ST_PROCESS_BODY_CL
							elif (CL_TE == 1):
								state = ST_PROCESS_BODY_TE
							else:
								state = ST_PROCESS_BODY_NODATA
								return (cls, dat_dec)
							break
						
			if (state == ST_PROCESS_BODY_CL):
				start = dat_dec.find("\r\n\r\n")+4
				#print ("%d %d " % (len(dat_raw)-start,size))
				if (len(dat_raw)-start) == size:
					return (cls, dat_dec)
			
			if (state == ST_PROCESS_BODY_TE):
				# FIXME: This is a terrible hack and can easily break
				# replace with an implementation that tracks the chunked lengths
				if dat_dec[-5:] == "0\r\n\r\n": 
					return (cls, dat_dec)


