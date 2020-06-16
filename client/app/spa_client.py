#!/usr/bin/python3
# -*- coding: utf-8 -*-

import spa
import json,sys,random,time,signal,threading,subprocess
import paho.mqtt.client as mqtt
from Crypto.Hash import SHA256

def ctrl_c_handler(sig, frame):
	global TERMINATING,client
	print('\nUSER INTERRUPT SIGNAL RECEIVED\n\nBye!')
	client.loop_stop()
	TERMINATING = True
	with open('session_id','w+') as f:
		f.seek(0)
		f.write("")
		f.truncate()
		f.close()				
	sys.exit(0)
signal.signal(signal.SIGINT, ctrl_c_handler)
	
def on_connect(client, userdata, flags, rc):
	global UID,CLIENT
	client.publish("up/"+UID+"/"+CLIENT, "CONNECTED")
	client.subscribe("sdp_ctrl/all/#")
	client.subscribe("dn/"+UID+"/"+CLIENT+"/#")
	print("CONNECTED TO SDP MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	print("MQTT SERVICE DISCONNECTED.")
	client.LOOP_STOP()

def on_message(client, userdata, msg):
	global SESSION_ID
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("[MQTT] "+ TOPIC+" : "+PAYLOAD)
	if PAYLOAD == "CONNECTED" and TOPIC == "sdp_ctrl/all":
		print("SDP SESSION ESTABLISHED")
		# Upon session establishment, increase local session counter by random int from 1 to 5
		spa.increase_counter()
	if PAYLOAD == "DISCONNECTED" and TOPIC == "sdp_ctrl/all":
		print("SDP SESSION DISCONNECTED BY SERVER")
		client.disconnect()
	else:
		T = TOPIC.split('/')
		if T[0] == "dn":
			USER = T[1] 
			CID = T[2]	
			CMD = T[3]
		if CMD == "session_id":
			print("UPDATE SESSION_ID = %s" %(PAYLOAD))
			with open('session_id','w+') as f:
				f.write(PAYLOAD)			
				
def TLS_LOOP():
	global GATEWAY_HOST,SESSION_ID,GATEWAY_TLS_PORT,client,TERMINATING,UID,CLIENT
	while not TERMINATING:
		if SESSION_ID != "":
			print("INITIATE TLS TUNNEL TO GATEWAY")
			print("\"ssh -D 60000 "+SESSION_ID+"@"+GATEWAY_HOST+" -p"+str(GATEWAY_TLS_PORT)+"\"")
			client.publish("up/"+UID+"/"+CLIENT, payload="TLS ESTABLISHED")
			subprocess.check_output("ssh -i /root/.ssh/id_rsa -D 60000 "+SESSION_ID+"@"+GATEWAY_HOST+" -p"+str(GATEWAY_TLS_PORT), shell=True)
			SESSION_ID = ""
	return
	

SDP_HOST = "sdp"
SDP_SPA_PORT = 60001
SDP_MQTT_PORT = 1883
GATEWAY_HOST = "gateway"
GATEWAY_TLS_PORT = 22
SESSION_ID = ""

print("SPA CLIENT STARTED")
SPA = spa.generate_spa()
print("   _______  ___ \n  / __/ _ \/ _ |\n _\ \/ ___/ __ |\n/___/_/  /_/ |_|\n\n%s\n" %(SPA.hex()))
if spa.send_spa(SDP_HOST,SDP_SPA_PORT,SPA):
	print("SPA PACKET DELIVERED to %s:%d" %(SDP_HOST,SDP_SPA_PORT))

print("TLS CLIENT STANDBY")
TERMINATING = False	
threading.Thread(target=TLS_LOOP,args=()).start()

print("INITIATE MQTT CLIENT...")
UID = spa.SESSION_UID.hex()
CLIENT = spa.SESSION_OTP.hex()
HASH = SHA256.new()
HASH.update((''.join([UID, CLIENT, spa.SESSION_CTR])).encode())
MSG_PWD = HASH.hexdigest()[:8]
client = mqtt.Client(client_id=CLIENT)
client.username_pw_set(UID, password=MSG_PWD)
client.will_set("up/"+UID+"/"+CLIENT, payload="DISCONNECTED")
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message
try:
	print("CONNECTING TO SDP MQTT SERVICE ...")
	time.sleep(1)
	client.connect(SDP_HOST, SDP_MQTT_PORT, 5)
	client.loop_forever()
except Exception as e:
	print("UNABLE TO CONNECT SDP MQTT SERVICE \n",str(e))
	
