#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json,sys,socket,threading,subprocess,time,os.path,atexit,os,glob,shutil
import mysql.connector
import paho.mqtt.client as mqtt
from mysql.connector import errorcode
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def At_Exit():
	Cleanup_Sessions()
	Restore_Firewall()
	print("\nBye!")

atexit.register(At_Exit) 
	
def Cleanup_Sessions():
	global mqttc
	print("DELETE RESIDUAL SESSION USERS")
	subprocess.check_output("rm -rf /home/*", shell=True)
	mqttc.publish("gateway/session/cleanup","")
	

def Restore_Firewall():
	global mqttc
	mqttc.publish("gateway/firewall/restore/default","")
	print("SET FIREWALL DEFAULTS")
	PREROUTING = subprocess.check_output("iptables -t nat -L PREROUTING -n --line-numbers", shell=True).split(b'\n')
	TOTAL_LINES = len(PREROUTING) - 3
	while TOTAL_LINES > 0:
		#iptables -t nat -D PREROUTING 1
		subprocess.check_output("iptables -t nat -D PREROUTING "+str(TOTAL_LINES), shell=True)
		TOTAL_LINES = TOTAL_LINES -1
	POSTROUTING = subprocess.check_output("iptables -t nat -L POSTROUTING -n --line-numbers", shell=True).split(b'\n')
	TOTAL_LINES = len(POSTROUTING) - 3
	while TOTAL_LINES > 0:
		#iptables -t nat -D POSTROUTING 1
		subprocess.check_output("iptables -t nat -D POSTROUTING "+str(TOTAL_LINES), shell=True)
		TOTAL_LINES = TOTAL_LINES -1		
	#iptables -P INPUT ACCEPT
	subprocess.check_output(["iptables", "-P", "INPUT", "ACCEPT"])
	#iptables -P FORWARD ACCEPT
	subprocess.check_output(["iptables", "-P", "FORWARD", "ACCEPT"])
	#iptables -F
	subprocess.check_output(["iptables", "-F", "INPUT"])
			
def Create_Session(UID, OTP, CTR, IP):
	global DB,SERVER_SEED,MQTT_PORT,MQTT_HOST_IP

	
def Local_Firewall_TCP22_Open_10s(IP):
	global MQTT_HOST_IP,MQTT_PORT,mqttc
	print("    --> FIREWALL ALLOW TCP22 ACCESS FOR %s" %(IP))
	#iptables -I INPUT 1 -p tcp -s 192.168.8.3 --dport 1883 -j ACCEPT
	subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", IP, "--dport", "22", "-j", "ACCEPT"])
	mqttc.publish("gateway/firewall/open/tcp22",IP)
	time.sleep(1000)
	print("    --> FIREWALL PREVENT NEW TCP22 ACCESS FOR %s" %(IP))
	# iptables -D INPUT -s 192.168.8.4/32 -p tcp -m tcp --dport 22 -j ACCEPT
	subprocess.check_output(["iptables", "-D", "INPUT", "-s", IP, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"])
	mqttc.publish("gateway/firewall/close/tcp22",IP)
	

def Initialize_Firewall_Rulles():
	# global MQTT_HOST_IP
	Restore_Firewall()
	print("INITIALIZ GATEWAY FIREWALL RULES")
	#iptables -I INPUT 1 -p tcp -s 192.168.8.3 --dport 1883 -j ACCEPT
	# subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", MQTT_HOST_IP, "--dport", "22", "-j", "ACCEPT"])
	#iptables -P INPUT DROP 
	subprocess.check_output(["iptables", "-P", "INPUT", "DROP"])
	#iptables -P FORWARD DROP 
	subprocess.check_output(["iptables", "-P", "FORWARD", "DROP"])
	# iptables -t nat -A POSTROUTING -j MASQUERADE
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
	#iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

def on_connect(client, userdata, flags, rc):
	client.publish("gateway", "CONNECTED", retain=True)
	client.subscribe("sdp_ctrl/gateway/#")
	client.subscribe("sdp_ctrl/all/#")
	print("CONNECTED TO MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	print("MQTT SERVICE DISCONNECTED")
	client.LOOP_STOP()

def init_message_client(MQTT_HOST_IP, MQTT_PORT, SERVER_SEED):
	client = mqtt.Client(client_id="00002")
	client.username_pw_set("gateway", password=SERVER_SEED)
	client.will_set("gateway", payload="DISCONNECTED", retain=True)
	client.on_connect = on_connect
	client.on_disconnect = on_disconnect
	client.on_message = on_message
	return client
	
def MQTT_LOOP(client):
	while 1:
		try:
			print("CONNECTING TO SDP MQTT SERVICE ...")
			client.connect(MQTT_HOST_IP, int(MQTT_PORT), 5) 
			client.loop_forever()
		except Exception as e:
			print("UNABLE TO CONNECT SDP MQTT SERVICE\n",str(e))
			time.sleep(2)

def on_message(client, userdata, msg):
	global SDP_CONNECTED,IPTABLE_QUEUE
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("[MQTT] "+ TOPIC+" : "+PAYLOAD)
	T = TOPIC.split('/')
	if PAYLOAD == "CONNECTED" and TOPIC == "sdp_ctrl/all":
		print("SDP SERVER CONNECTED")
		SDP_CONNECTED = True
	elif PAYLOAD == "DISCONNECTED" and TOPIC == "sdp_ctrl/all":
		print("SDP SERVER DISCONNECTED")
		SDP_CONNECTED = False
	else:
		if TOPIC == "sdp_ctrl/gateway/connection/open":	
			SESSION_CONFIG = json.loads(PAYLOAD)
			
			print("GATEWAY OPEN mTLS CONNECTION FOR SESSION CLIENT - ")
			# Update local reverse proxy setting based on AUTHORIZED_SERVICES
			AUTHORIZED_SERVICES = json.loads(SESSION_CONFIG['AUTHORIZED_SVC'])
			print("--> AUTHORIZED SERVICES:")
			print(AUTHORIZED_SERVICES)
			client.publish("gateway/config/reverse_proxy/auth_svc", SESSION_CONFIG['AUTHORIZED_SVC'][:20]+"...")

			# Create dynamic session user account
			print("--> CREATE SESSION USER ACCOUNT %s" %(SESSION_CONFIG['session_id']))
			subprocess.check_output(["useradd", "-m", SESSION_CONFIG['session_id']])
			client.publish("gateway/user/add/account", SESSION_CONFIG['session_id'])
			os.makedirs('/home/'+SESSION_CONFIG['session_id']+'/.ssh')
			with open('/home/'+SESSION_CONFIG['session_id']+'/.ssh/authorized_keys','w+') as f:
				f.write(SESSION_CONFIG['RSA_PUB_KEY'])
			print("--> SESSION USER CREATED, ACCESS FROM CLIENT DEVICE BY:")
			print("    -->  $> ssh %s@gateway" %(SESSION_CONFIG['session_id']))
			client.publish("gateway/user/add/pubkey", SESSION_CONFIG['RSA_PUB_KEY'][:20]+"...")
			
			# Open up firewall for session client
			print("--> OPEN SSH PORT (TCP22) FOR %s" %(SESSION_CONFIG['session_ip']))
			IPTABLE_QUEUE.append(SESSION_CONFIG['session_ip'])
			
		if TOPIC == "sdp_ctrl/gateway/connection/close":			
			SESSION_CONFIG = json.loads(PAYLOAD)
			print(SESSION_CONFIG['session_ip'])
			print("GATEWAY CLOSE mTLS CONNECTION FOR SESSION CLIENT")
			# Disconnect all process through this session TLS tunnel
			print("--> DISCONNECT ALL COMMUNICATIONS FROM %s" %(SESSION_CONFIG['session_ip']))
			try:
				subprocess.check_output(["pkill", "-KILL", "-u", SESSION_CONFIG['session_id']])
				client.publish("gateway/connection/kill/session_id", SESSION_CONFIG['session_id'])
			except:
				pass	
			
			# Delete dynamic session user account and public key
			print("--> DELETE SESSION USER ACCOUNT %s" %(SESSION_CONFIG['session_id']))
			try:
				subprocess.check_output(["userdel", "-f", SESSION_CONFIG['session_id']])
				shutil.rmtree("/home/"+SESSION_CONFIG['session_id'])
				client.publish("gateway/user/delete/account", SESSION_CONFIG['session_id'])
			except:
				pass				
			print("OK")
				
# Main program	

print("Initialize server configurations")
with open('config','r') as f:
    CONFIG = json.loads(f.read())
if "MQTT_HOST_IP" not in CONFIG:
	MQTT_HOST_IP = socket.gethostbyname(CONFIG['MQTT_HOST_NAME'])
else:
	MQTT_HOST_IP = CONFIG['MQTT_HOST_IP']
MQTT_PORT = CONFIG['MQTT_PORT']
SERVER_SEED=CONFIG['SERVER_SEED']
SDP_CONNECTED = False

print("Initialize message client")
mqttc = init_message_client(MQTT_HOST_IP,MQTT_PORT,SERVER_SEED)

print("Initialize firewal rulls")	
Initialize_Firewall_Rulles()

print("Start Message Loops")
threading.Thread(target=MQTT_LOOP,args=(mqttc,)).start()

print("Start Gateway Manager")

IPTABLE_QUEUE = []
while True:
	if IPTABLE_QUEUE != []:
		threading.Thread(target=Local_Firewall_TCP22_Open_10s,args=(IPTABLE_QUEUE.pop(0),)).start()
		
	
