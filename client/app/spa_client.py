#!/usr/bin/python3
# -*- coding: utf-8 -*-

import spa
import json,sys,random,time,signal,threading,subprocess,os
import paho.mqtt.client as mqtt
from Crypto.Hash import SHA256

def ctrl_c_handler(sig, frame):
	global TERMINATING,client,CLIENT,SESSION_ID
	# subprocess.check_output("echo '1' > e",shell=True)
	client.publish("up/"+UID+"/"+CLIENT+"/"+SESSION_ID, "DISCONNECTED")
	client.disconnect()
	TERMINATING = True
	with open('session_id','w+') as f:
		f.seek(0)
		f.write("")
		f.truncate()
		f.close()	
	print('USER INTERRUPT SIGNAL RECEIVED\n\nBye!')	
	sys.exit(0)
signal.signal(signal.SIGINT, ctrl_c_handler)
signal.signal(signal.SIGTERM, ctrl_c_handler)
	
def on_connect(client, userdata, flags, rc):
	global UID,CLIENT,MQTT_CONNECTED
	MQTT_CONNECTED = True
	client.publish("up/"+UID+"/"+CLIENT, "CONNECTED")
	client.subscribe("sdp_ctrl")
	client.subscribe("gateway")
	client.subscribe("dn/"+UID+"/"+CLIENT+"/#")
	print("CONNECTED TO SDP MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	global TERMINATING
	print("\nMQTT SERVICE DISCONNECTED.")
	client.loop_stop()
	TERMINATING = True

def on_message(client, userdata, msg):
	global SESSION_ID
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("\033[1;36m[MQTT] "+ TOPIC+" : "+PAYLOAD+"\033[0m")
	if PAYLOAD == "CONNECTED" and TOPIC == "sdp_ctrl":
		print("SDP SESSION ESTABLISHED")
		# Upon session establishment, increase local session counter by random int from 1 to 5
		spa.increase_counter()
	elif PAYLOAD == "DISCONNECTED" and TOPIC == "sdp_ctrl":
		print("SDP SESSION DISCONNECTED BY SERVER")
		client.disconnect()
	elif PAYLOAD == "DISCONNECTED" and TOPIC == "gateway":
		print("SDP SESSION DISCONNECTED BY GATEWAY")
		client.disconnect()
		os._exit(1)
	else:
		T = TOPIC.split('/')
		if T[0] == "dn":
			USER = T[1] 
			CID = T[2]	
			CMD = T[3]
		if CMD == "session_id":
			SESSION_ID = PAYLOAD
			print("UPDATE SESSION_ID = %s" %(PAYLOAD))
			with open('session_id','w+') as f:
				f.write(PAYLOAD)	
			print("SEND SESSION_ACK")
			client.publish("up/"+UID+"/"+CLIENT+"/session_ack/"+SESSION_ID,"ACK")
			print("\033[1;32m        ______ __    ____\n  __ _ /_  __// /   / __/\n /  ' \ / /  / /__ _\ \  \n/_/_/_//_/  /____//___/\n\033[0m")

def MQTT_LOOP(client):
	global SDP_HOST,SDP_MQTT_PORT,TERMINATING
	while not TERMINATING:
		try:
			print("CONNECTING TO SDP MQTT SERVICE ...")
			client.connect(SDP_HOST, int(SDP_MQTT_PORT), 5)
			client.loop_forever()
		except Exception as e:
			print("UNABLE TO CONNECT SDP MQTT SERVICE\n",str(e))
			os._exit(1)

def MQTT_KEEPALIVE(client):
	global CLIENT,UID,MQTT_CONNECTED
	while 1:
		if MQTT_CONNECTED:
			print("SEND HEARTBEAT TO SDP SERVER")
			client.publish("up/"+UID+"/"+CLIENT+"/hb", "")
		time.sleep(60)			

def WAIT_FOR_SESSION_ID():
	global SESSION_ID,WAITING,TERMINATING
	WAITING = False
	time.sleep(5)
	if SESSION_ID == "":
		print("NO SESSION_ID RECEIVED, QUIT")
		TERMINATING = True
		
with open('/app/config','r') as f:
	CONFIG = json.loads(f.read())
SDP_HOST = CONFIG["SDP_HOST"]
SDP_SPA_PORT = CONFIG["SDP_SPA_PORT"]
SDP_MQTT_PORT = CONFIG["SDP_MQTT_PORT"]
GATEWAY_HOST = CONFIG["GATEWAY_HOST"]
GATEWAY_TLS_PORT = CONFIG["GATEWAY_TLS_PORT"]
SESSION_ID = ""
MQTT_CONNECTED = False

print("SPA CLIENT STARTED")
SPA = spa.generate_spa()
print("\033[1;33m   _______  ___ \n  / __/ _ \/ _ |\n _\ \/ ___/ __ |\n/___/_/  /_/ |_|\n\n\033[0m%s\n" %(SPA.hex()))
if spa.send_spa(SDP_HOST,SDP_SPA_PORT,SPA):
	print("SPA PACKET DELIVERED to %s:%d" %(SDP_HOST,SDP_SPA_PORT))

TERMINATING = False	
WAITING = True

print("INITIATE MQTT CLIENT...")
UID = spa.SESSION_UID.hex()
CLIENT = spa.SESSION_OTP.hex()
print(" - client = %s" %(CLIENT))
print(" - user = %s" %(UID))
HASH = SHA256.new()
HASH.update((''.join([UID, CLIENT, spa.SESSION_CTR])).encode())
MSG_PWD = HASH.hexdigest()[:8]
print(" - passwd = %s" %(MSG_PWD))
client = mqtt.Client(client_id=CLIENT)
client.username_pw_set(UID, password=MSG_PWD)
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message

print("START MQTT LOOP")
time.sleep(0.5)
threading.Thread(target=MQTT_LOOP,args=(client,)).start()
# threading.Thread(target=MQTT_KEEPALIVE,args=(client,)).start()

while not TERMINATING:
	if WAITING:
		threading.Thread(target=WAIT_FOR_SESSION_ID,args=()).start()
	time.sleep(1)
