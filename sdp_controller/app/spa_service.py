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

class Database:
	conn = None
	def connect(self):
		global DB_HOST,DB_PORT,DB_USER,DB_PWD,DB_DB
		self.conn = mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PWD, database=DB_DB, autocommit=True)	
	def query(self, sql):
		try:
			cursor = self.conn.cursor(dictionary=True)
			cursor.execute(sql)	
			print('DB OPERATION OK')
		except mysql.connector.OperationalError as err:
			print(err.errno)
			print(err.sqlstate)
			print(err.msg)
			print('DB NOT CONNECTED, RETRY')
			self.connect()
			cursor = self.conn.cursor(dictionary=True)
			cursor.execute(sql)				
		except mysql.connector.Error as err:
			print(err)
		except:
			print('DB NOT CONNECTED, RETRY')
			self.connect()
			cursor = self.conn.cursor(dictionary=True)
			cursor.execute(sql)					
		return cursor
	
def Cleanup_Sessions():
	global DB
	print("CLEANUP SESSIONS AND ACL")
	DB.query("DELETE FROM `vmq_auth_acl` WHERE length(`client_id`) > 8")

def Delete_User_Session(CLIENT_ID):
	global DB,GATEWAY_ONLINE,mqttc,SESSION_LIST
	SESSION_CONFIG = SESSION_LIST[CLIENT_ID]
	del SESSION_CONFIG['RSA_PUB_KEY']
	del SESSION_CONFIG['AUTHORIZED_SVC']
	del SESSION_LIST[CLIENT_ID]
	SESSION_ID = SESSION_CONFIG['session_id']
	print("DELETE USER SESSION AND ACL - %s" %(SESSION_ID))
	DB.query("DELETE FROM `vmq_auth_acl` WHERE `session_id`='"+SESSION_ID+"'")
	if GATEWAY_ONLINE:
		print("CLOSE mTLS CONNECTION FOR %s" %(SESSION_ID))
		print("DELERE FIREWALL RULES ON GATEWAY")
		mqttc.publish("sdp_ctrl/gateway/connection/close", json.dumps(SESSION_CONFIG))
	else:
		print("GATEWAY NOT ONLINE")

def Create_Session(UID, OTP, IP, CONF):
	global DB,SERVER_SEED,MQTT_PORT,MQTT_HOST_IP,SESSION_LIST,SESSION_QUEUE
	# Create session user ACL for client
	HASH = SHA256.new()
	HASH.update((''.join([UID, OTP, str(CONF['SPA_CTR'])])).encode())
	MSG_PWD = HASH.hexdigest()[:8]
	# Create session config for client
	HASH = SHA256.new()
	HASH.update((''.join([UID, str(time.time()), SERVER_SEED])).encode())
	SESSION_ID = HASH.hexdigest()[:8]	
	PUB_ACL = '[{"pattern":"up/%u/%c/#"}]'
	SUB_ACL = '[{"pattern":"dn/%u/%c/#"},{"pattern":"sdp_ctrl"},{"pattern":"gateway"}]'
	# try:
	cursor = DB.query("SELECT * FROM `vmq_auth_acl` WHERE `client_id` = '"+OTP+"'")
	SESSION_CLIENT = cursor.fetchall()
	if SESSION_CLIENT == []:
		DB.query("INSERT INTO `vmq_auth_acl`(`status`,`mountpoint`, `client_id`, `username`, `password`, `publish_acl`, `subscribe_acl`, `session_ip`, `session_id`) VALUES ('pending','','"+OTP+"','"+UID+"',password('"+MSG_PWD+"'),'"+PUB_ACL+"','"+SUB_ACL+"','"+IP+"','"+SESSION_ID+"')")
		print("ADDED NEW SESSION ACL - USER:%s, CLIENT:%s" %(UID,OTP))
		SESSION = {}
		# session_id,session_ip,RSA_PUB_KEY,AUTHORIZED_SVC
		SESSION["session_id"] = SESSION_ID
		SESSION["session_ip"] = IP
		SESSION["RSA_PUB_KEY"] = CONF["RSA_PUB_KEY"]
		SESSION["AUTHORIZED_SVC"] = CONF["AUTHORIZED_SVC"]
		SESSION_LIST[OTP] = SESSION
		SESSION_QUEUE.append(OTP)
	else:
		# when a user client identified as potentially compromised, 
		# disconnect all sessions from the same user		
		print("SESSION CLIENT EXISTS, DISCONNECT CLIENT")
		print("--> DELETE ALL SESSIONS FROM IP ADDR "+IP) 
		DB.query("DELETE FROM `vmq_auth_acl` WHERE `username`='"+UID+"' AND `session_ip`='"+IP+"'")	
		print("--> DELETE FIREWALL RULES FOR "+IP) 
		PREROUTING = subprocess.check_output("iptables -t nat -L PREROUTING -n -v --line-numbers | grep "+IP, shell=True).strip().split(b'\n')
		TOTAL_LINES = len(PREROUTING)
		# print(TOTAL_LINES)			
		while TOTAL_LINES > 0:
			subprocess.check_output(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", IP, "-p", "tcp", "--dport", str(MQTT_PORT), "-j", "DNAT", "--to-destination", MQTT_HOST_IP+":"+str(MQTT_PORT)])
			TOTAL_LINES = TOTAL_LINES - 1
		return			
	# except Exception as e:
		# print(str(e))
		# return
	print("CREATED NEW SESSION ID =", SESSION_ID)
	Local_Firewall_P1883_Open_10s(IP)

def Sync_Counter(UID,CTR):
	global DB
	print("UPDATE SERVER SESSION COUNTER: %d" %(CTR))
	DB.query("UPDATE `users` SET `SPA_CTR`="+str(CTR)+" WHERE `UID`='"+UID+"'")
	
def Local_Firewall_P1883_Open_10s(IP):
	global MQTT_HOST_IP,MQTT_PORT
	print("FIREWALL ALLOW MSG SERVER ACCESS FOR -", IP)
	# iptables -t nat -A PREROUTING -s 192.168.8.3 -p tcp --dport 1883 -j DNAT --to-destination 192.168.8.4:1883
	subprocess.check_output(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", IP, "-p", "tcp", "--dport", str(MQTT_PORT), "-j", "DNAT", "--to-destination", MQTT_HOST_IP+":"+str(MQTT_PORT)])
	#iptables -I INPUT 1 -p tcp -s 192.168.8.3 --dport 1883 -j ACCEPT
	# subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", IP, "--dport", "1883", "-j", "ACCEPT"])	

def SPA_LOOP(SPA_PORT):
	SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	SOCKET.bind(("", SPA_PORT))
	while True:
		data, addr = SOCKET.recvfrom(64)
		threading.Thread(target=Validate_SPA,args=(data,addr)).start()
	
def Validate_SPA(DATA, ADDR):
	global DB,SERVER_SEED,SERVER_SHARED_IV,SERVER_SHARED_KEY,GATEWAY_ONLINE,MQTT_CONNECTED
	if not MQTT_CONNECTED:
		print("MQTT NOT CONNECTED!")
		return	
	if not GATEWAY_ONLINE:
		print("GATEWAY NOT CONNECTED!")
		return
	print("DATA ARRIVES",DATA.hex())
	if len(DATA) != 32: # check if packet size is 32, which is the default lenth for our SPA format 
		return
	print("   _______  ___ \n  / __/ _ \/ _ |\n _\ \/ ___/ __ |\n/___/_/  /_/ |_|\n\n%s\n" %(DATA.hex()))
	CIPHER_OBJ = AES.new(SERVER_SHARED_KEY, AES.MODE_CBC, SERVER_SHARED_IV)
	DEC_DATA = CIPHER_OBJ.decrypt(DATA)
	# print("R_DATA="+DEC_DATA.hex())
	# return
	REQ_UID = DEC_DATA[0:8]
	REQ_UID_HEX = REQ_UID.hex()
	REQ_OTP = DEC_DATA[8:16]
	REQ_GMAC = DEC_DATA[16:]
	# with open('users','r') as f:
		# USERS = json.loads(f.read())
	cursor = DB.query("SELECT * FROM users WHERE UID = '"+REQ_UID_HEX+"'")
	USER = cursor.fetchall()
	if USER == []:
		print("SPA INVALID - USER NOT FOUND")
		return
	# print(USER)
	USER_SPA_CTR = bytes.fromhex(("0000000000000000"+hex(USER[0]["SPA_CTR"])[2:])[-16:])
	HASH = SHA256.new()
	HASH.update(b''.join([REQ_UID,bytes.fromhex(SERVER_SEED),USER_SPA_CTR]))
	SERVER_OTP = bytes.fromhex(HASH.hexdigest()[:16])
	# print("S_OTP="+SERVER_OTP.hex())
	# print("R_OTP="+REQ_OTP.hex())
	# return
	i = 0
	while SERVER_OTP != REQ_OTP:
		i = i + 1
		if i > 5: # session counter will try 5 times, each time increase by 1
			print("SPA INVALID - COUNTER VALUE")
			return	
		USER_SPA_CTR = bytes.fromhex(("0000000000000000"+hex(USER[0]["SPA_CTR"]+i)[2:])[-16:])
		HASH = SHA256.new()
		HASH.update(b''.join([REQ_UID,bytes.fromhex(SERVER_SEED),USER_SPA_CTR]))
		SERVER_OTP = bytes.fromhex(HASH.hexdigest()[:16])		
	print("SPA FROM %s VALIDATED" %(REQ_UID_HEX))
	Sync_Counter(REQ_UID_HEX, USER[0]["SPA_CTR"]+i)
	USER[0]["SPA_CTR"] = USER[0]["SPA_CTR"]+i
	Create_Session(REQ_UID_HEX, REQ_OTP.hex(), ADDR[0], USER[0])

def Restore_Firewall():
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
	
def Initialize_Firewall_Rulles():
	time.sleep(0.5)
	Restore_Firewall()
	time.sleep(1.5)
	print("INITIALIZE SDP FIREWALL RULES")
	time.sleep(0.5)
	#iptables -P INPUT DROP 
	subprocess.check_output(["iptables", "-P", "INPUT", "DROP"])
	#iptables -P FORWARD DROP 
	subprocess.check_output(["iptables", "-P", "FORWARD", "ACCEPT"])
	#iptables -A INPUT -p udp --dport 60001 -j ACCEPT
	subprocess.check_output(["iptables", "-A", "INPUT", "-p", "udp", "--dport", "60001", "-j", "ACCEPT"])
	# iptables -t nat -A POSTROUTING -j MASQUERADE
	subprocess.check_output(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])	
	#iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
	#iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	subprocess.check_output(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
	print("FIREWALL RULES READY")
	time.sleep(0.5)

def on_connect(client, userdata, flags, rc):
	global MQTT_CONNECTED
	MQTT_CONNECTED = True
	time.sleep(1)
	client.publish("sdp_ctrl", "CONNECTED", retain=True)
	client.subscribe("up/#")
	client.subscribe("gateway/#")
	print("CONNECTED TO MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	global MQTT_CONNECTED
	MQTT_CONNECTED = False
	print("MQTT SERVICE DISCONNECTED (%d)" %(rc))
	time.sleep(2)
	if rc != 5:
		try:
			client.disconnect()
		except:
			pass

def init_mqtt_client(MQTT_HOST_IP, MQTT_PORT, SERVER_SEED):
	subprocess.check_output("iptables -P INPUT ACCEPT", shell=True)
	client = mqtt.Client(client_id="00001")
	client.username_pw_set("sdp_ctrl", password=SERVER_SEED)
	client.will_set("sdp_ctrl", payload="DISCONNECTED", retain=True)
	client.on_connect = on_connect
	client.on_disconnect = on_disconnect
	client.on_message = on_message
	return client
	
def MQTT_LOOP(client):
	global INIT_MQTT,INIT_FIREWALL
	while not INIT_MQTT:
		try:
			print("CONNECTING TO SDP MQTT SERVICE ...")
			client.connect(MQTT_HOST_IP, int(MQTT_PORT), 5)
			client.loop_forever()
		except Exception as e:
			print("UNABLE TO CONNECT SDP MQTT SERVICE\n",str(e))
			time.sleep(2)
			INIT_MQTT = True
			INIT_FIREWALL = True
				
def MQTT_KEEPALIVE(client):
	global MQTT_CONNECTED
	while 1:
		if MQTT_CONNECTED:
			client.publish("sdp_ctrl/hb", "", 1)
		time.sleep(59)
				
def on_message(client, userdata, msg):
	global DB,GATEWAY_ONLINE,SESSION_LIST,INIT_FIREWALL
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("\033[1;36m[MQTT] "+ TOPIC+" : "+PAYLOAD+"\033[0m")
	T = TOPIC.split('/')
	if T[0] == "up":
		USER = T[1] 
		CID = T[2]		
		if PAYLOAD == "CONNECTED":
			if CID not in SESSION_LIST:
				print("CLIENT ACCESS EXPIRED")
			SESSION_CLIENT = SESSION_LIST[CID]
			time.sleep(0.5)
			print("SEND SESSION ID TO CLIENT")
			print(" -- dn/"+USER+"/"+CID+"/session_id\n -- "+SESSION_CLIENT['session_id'])
			try:
				client.publish("dn/"+USER+"/"+CID+"/session_id", SESSION_CLIENT['session_id'], 2)
				# Then wait for Session Acknowledgement from Client			
			except Exception as e:
				print(e)
		elif PAYLOAD == "ACK":
			# Sample ACK: up/[username]/[client_id]/session_ack/[session_id], "ACK"
			if T[3] == "session_ack":
				if GATEWAY_ONLINE:
					SESSION_ID = T[4]	
					# Increase user session counter by 1 upon session client connection
					DB.query("UPDATE `users` SET `SPA_CTR`=`SPA_CTR`+1 WHERE `UID` = '"+USER+"'")				
					print("RECEIVED SESSION_ACK FROM CLIENT FOR - %s" %(SESSION_ID))
					print("USER %s-%s AUTH OK, ESTABLISH mTLS CONNECTION" %(USER,CID))
					client.publish("sdp_ctrl/gateway/connection/open", json.dumps(SESSION_LIST[CID]), 2) 
					# Update session status
					DB.query("UPDATE `vmq_auth_acl` SET `status`='connected' WHERE `session_id` = '"+SESSION_ID+"'")						
				else:
					print("GATEWAY NOT CONNECTED")
			else:
				pass
		elif PAYLOAD == "DISCONNECTED":
			SESSION_ID = T[3]	
			Delete_User_Session(CID)
	elif T[0] == "gateway":	
		if PAYLOAD == "CONNECTED":
			GATEWAY_ONLINE = True
		elif PAYLOAD == "DISCONNECTED":
			GATEWAY_ONLINE = False
		elif T[1] == "aloha":
			# INIT_FIREWALL = True
			client.publish("sdp_ctrl/gateway/aloha","")
			pass
	
def Wait_for_Session_ACK(CLIENT_ID):
	global DB,SESSION_LIST
	print("SESSION ACK CHECK STARTED ...")
	N = 0
	while CLIENT_ID in SESSION_LIST:
		time.sleep(1)
		N = N + 1
		if N == 5:
			SESSION_ID = SESSION_LIST[CLIENT_ID]['session_id']
			print("CHECK IF SESSION IS CONNECTED - %s" %(SESSION_ID))
			cursor = DB.query("SELECT `status` FROM `vmq_auth_acl` WHERE `session_id` = '"+SESSION_ID+"'")
			RESULTS = cursor.fetchall()
			if RESULTS != []:
				if RESULTS[0]['status'] == "pending":
					print("NO SESSION_ACK RECEIVED, DELETE SESSION")
					Delete_User_Session(CLIENT_ID)
				else:
					print("SESSION ACK HANDLED")
			return
	print("SESSION ACK RECEIVED")
	
# Main program	

print("Initialize server configurations")
with open('/app/config','r') as f:
    CONFIG = json.loads(f.read())
SPA_PORT = int(CONFIG['SPA_PORT'])
SERVER_SHARED_KEY = bytes.fromhex(CONFIG['SERVER_SHARED_KEY'])
SERVER_SHARED_IV = bytes.fromhex(CONFIG['SERVER_SHARED_IV'])
SERVER_SEED = CONFIG['SERVER_SEED']
DB_HOST = CONFIG['DB_HOST']
DB_PORT = CONFIG['DB_PORT']
DB_USER = CONFIG['DB_USER']
DB_PWD = CONFIG['DB_PWD']
DB_DB = CONFIG['DB_DB']

if "MQTT_HOST_IP" not in CONFIG:
	MQTT_HOST_IP = socket.gethostbyname(CONFIG['MQTT_HOST_NAME'])
else:
	MQTT_HOST_IP = CONFIG['MQTT_HOST_IP']
MQTT_PORT = CONFIG['MQTT_PORT']

print("Connecting to database")
DB = Database()

print("Initialize sessions")
Cleanup_Sessions()	

print("Start UDP server AT PORT %s" %(SPA_PORT))
threading.Thread(target=SPA_LOOP,args=(SPA_PORT,)).start()

SESSION_LIST = {}
SESSION_QUEUE = []
INIT_MQTT = True
MQTT_CONNECTED = False
EXITING = False
INIT_FIREWALL = True
while not EXITING:
	if INIT_MQTT:
		INIT_MQTT = False
		print("Initialize message client")
		mqttc = init_mqtt_client(MQTT_HOST_IP,MQTT_PORT,SERVER_SEED)
		print("Start message loop")
		threading.Thread(target=MQTT_LOOP,args=(mqttc,)).start()
		# threading.Thread(target=MQTT_KEEPALIVE,args=(mqttc,)).start()
	if INIT_FIREWALL:
		time.sleep(1)
		INIT_FIREWALL = False
		print("Initialize firewal rulls")	
		threading.Thread(target=Initialize_Firewall_Rulles,args=()).start()
	if SESSION_QUEUE != []:
		CLIENT_ID = SESSION_QUEUE.pop()
		threading.Thread(target=Wait_for_Session_ACK,args=(CLIENT_ID,)).start()
	time.sleep(1)

