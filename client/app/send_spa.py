#!/usr/bin/python
# -*- coding: utf-8 -*-

# command example: python send_spa.py [HOST] [PORT] [SPA]
import socket,sys

if len(sys.argv) != 4:
	sys.exit()

SDP_HOST = sys.argv[1]
SDP_PORT = int(sys.argv[2])
SDP_SPA = sys.argv[3]
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCKET.sendto(bytes.fromhex(SDP_SPA), (SDP_HOST, SDP_PORT))
print(SDP_SPA)
