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
	global mqttc,MQTT_CONNECTED
	print("SHUTDOWN TUNNEL SERVER")
	subprocess.check_output("service ssh stop", shell=True)
	print("DELETE RESIDUAL SESSION USERS")
	USERS = subprocess.check_output("awk -F':' '/1000::\/home/{print $1}' /etc/passwd", shell=True).split()
	for USER in USERS: 
		print(USER)
		try:
			subprocess.check_output(["pkill", "-f", USER])
		except Exception as e:
			print(str(e))
			pass			
		try:
			# userdel -r XXX
			subprocess.check_output("userdel -r "+USER.decode(), shell=True)  
		except Exception as e:
			print(str(e))
			pass
	subprocess.check_output("rm -rf /home/*", shell=True)
	if MQTT_CONNECTED:
		try:
			mqttc.publish("gateway/session/cleanup","")
		except:
			pass
	

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
	global SERVER_SEED,MQTT_PORT,MQTT_HOST_IP

def Check_Connection(ID):
	global MQTT_HOST_IP,MQTT_PORT,mqttc
	N = 0
	while subprocess.call('ps aux | grep "sshd: '+ID+'" | grep -v grep',shell=True):
		# print("N=%d" %(N))
		time.sleep(0.2)
		N = N + 0.2
		if N > 5: 	
			return
	print("\033[1;32m        ______ __    ____\n  __ _ /_  __// /   / __/\n /  ' \ / /  / /__ _\ \  \n/_/_/_//_/  /____//___/\n\033[0m")
	mqttc.publish("gateway/mtls/connection/"+ID, "ESTABLISHED")	
	
def Local_Firewall_TCP22_Open_10s(IP):
	global MQTT_HOST_IP,MQTT_PORT,mqttc
	print("    --> FIREWALL ALLOW TCP22 ACCESS FOR %s" %(IP))
	#iptables -I INPUT 1 -p tcp -s 192.168.8.3 --dport 1883 -j ACCEPT
	subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", IP, "--dport", "22", "-j", "ACCEPT"])
	mqttc.publish("gateway/firewall/open/tcp22",IP)
	time.sleep(5)
	print("    --> FIREWALL PREVENT NEW TCP22 ACCESS FOR %s" %(IP))
	# iptables -D INPUT -s 192.168.8.4/32 -p tcp -m tcp --dport 22 -j ACCEPT
	subprocess.check_output(["iptables", "-D", "INPUT", "-s", IP, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"])
	mqttc.publish("gateway/firewall/close/tcp22",IP)

def Initialize_Firewall_Rulles():
	Restore_Firewall()
	time.sleep(0.5)
	print("INITIALIZ GATEWAY FIREWALL RULES")
	time.sleep(0.5)
	#iptables -P INPUT DROP 
	subprocess.check_output(["iptables", "-P", "INPUT", "DROP"])
	#iptables -P FORWARD DROP 
	subprocess.check_output(["iptables", "-P", "FORWARD", "DROP"])
	# iptables -t nat -A POSTROUTING -j MASQUERADE
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
	#iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
	print("FIREWALL RULES READY")
	time.sleep(0.5)	

def on_connect(client, userdata, flags, rc):
	global MQTT_CONNECTED
	MQTT_CONNECTED = True
	time.sleep(1)
	client.publish("gateway", "CONNECTED", retain=True)
	client.subscribe("sdp_ctrl/gateway/#")
	client.subscribe("sdp_ctrl")
	print("CONNECTED TO MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	global MQTT_CONNECTED
	MQTT_CONNECTED = False
	print("MQTT SERVICE DISCONNECTED (%d)" %(rc))
	time.sleep(5)
	if rc != 5:
		try:
			client.disconnect()
		except:
			pass

def init_message_client(MQTT_HOST_IP, MQTT_PORT, SERVER_SEED):
	subprocess.check_output("iptables -P INPUT ACCEPT", shell=True)
	client = mqtt.Client(client_id="00002")
	client.username_pw_set("gateway", password=SERVER_SEED)
	client.will_set("gateway", payload="DISCONNECTED", retain=True)
	client.on_connect = on_connect
	client.on_disconnect = on_disconnect
	client.on_message = on_message
	return client
	
def MQTT_KEEPALIVE(client):
	global MQTT_CONNECTED
	while 1:
		if MQTT_CONNECTED:
			client.publish("gateway/hb", "", 1)
		time.sleep(59)	
		
def MQTT_LOOP(client):
	global INIT_MQTT
	while not INIT_MQTT:
		try:
			print("CONNECTING TO SDP MQTT SERVICE ...")
			client.connect(MQTT_HOST_IP, int(MQTT_PORT), 20) 
			client.loop_forever()
		except Exception as e:
			print("UNABLE TO CONNECT SDP MQTT SERVICE\n",str(e))
			time.sleep(2)
			INIT_MQTT = True
	
				
def on_message(client, userdata, msg):
	global SDP_CONNECTED,IPTABLE_QUEUE,CONNECTION_QUEUE
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("\033[1;36m[MQTT] "+ TOPIC+" : "+PAYLOAD+"\033[0m")
	T = TOPIC.split('/')
	if PAYLOAD == "CONNECTED" and TOPIC == "sdp_ctrl":
		print("SDP SERVER CONNECTED")
		client.publish("gateway/aloha","")
		SDP_CONNECTED = True
	elif PAYLOAD == "DISCONNECTED" and TOPIC == "sdp_ctrl":
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
			client.publish("gateway/config/reverse_proxy/"+SESSION_CONFIG['session_id']+"/auth_svc", SESSION_CONFIG['AUTHORIZED_SVC'][:20]+"...")

			# Create dynamic session user account
			print("--> CREATE SESSION USER ACCOUNT %s" %(SESSION_CONFIG['session_id']))
			subprocess.check_output(["useradd", "-g", "SDP", "-m", SESSION_CONFIG['session_id']])
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
			CONNECTION_QUEUE.append(SESSION_CONFIG['session_id'])
		if TOPIC == "sdp_ctrl/gateway/connection/close":			
			SESSION_CONFIG = json.loads(PAYLOAD)
			print(SESSION_CONFIG['session_ip'])
			print("GATEWAY CLOSE mTLS CONNECTION FOR SESSION CLIENT")
			# Disconnect all process through this session TLS tunnel
			print("--> DISCONNECT ALL COMMUNICATIONS FROM %s" %(SESSION_CONFIG['session_ip']))
			try:
				subprocess.check_output(["pkill", "-KILL", "-u", SESSION_CONFIG['session_id']])
				client.publish("gateway/mtls/connection/"+SESSION_CONFIG['session_id'], "CLOSED")
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
with open('/app/config','r') as f:
    CONFIG = json.loads(f.read())
if "MQTT_HOST_IP" not in CONFIG:
	MQTT_HOST_IP = socket.gethostbyname(CONFIG['MQTT_HOST_NAME'])
else:
	MQTT_HOST_IP = CONFIG['MQTT_HOST_IP']
MQTT_PORT = CONFIG['MQTT_PORT']
SERVER_SEED=CONFIG['SERVER_SEED']

print("Start Gateway Manager")

IPTABLE_QUEUE = []
CONNECTION_QUEUE = []
SDP_CONNECTED = False
MQTT_CONNECTED = False
INIT_MQTT = True
EXITING = False
while not EXITING:
	if IPTABLE_QUEUE != []:
		threading.Thread(target=Local_Firewall_TCP22_Open_10s,args=(IPTABLE_QUEUE.pop(0),)).start()
		threading.Thread(target=Check_Connection,args=(CONNECTION_QUEUE.pop(0),)).start()
	time.sleep(1)
	if INIT_MQTT:
		INIT_MQTT = False
		print("Initialize tunnel server")
		Cleanup_Sessions()
		subprocess.check_output("service ssh restart", shell=True)		
		print("Initialize message client")
		mqttc = init_message_client(MQTT_HOST_IP,MQTT_PORT,SERVER_SEED)		
		print("Start Message Loops")
		threading.Thread(target=MQTT_LOOP,args=(mqttc,)).start()
		# threading.Thread(target=MQTT_KEEPALIVE,args=(mqttc,)).start()
		time.sleep(1)
		print("Initialize firewal rulls")	
		Initialize_Firewall_Rulles()
	
