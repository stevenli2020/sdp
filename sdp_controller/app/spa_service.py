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

def Disconnect_User(UID):
	pass
	
def Delete_User(UID):
	print("Delete user:",UID)
	try:
		#userdel -f [UID]
		subprocess.check_output(["userdel", "-f", UID])
		print(" > Deleted session user -",UID)
	except:
		pass
	try:
		shutil.rmtree("/home/"+UID)
	except:
		pass
	
def Delete_Session(UID):
	SESSION_ID = UID[0:16]
	print("Delete session:",SESSION_ID)
	try:
		os.remove("/app/sessions/"+SESSION_ID)
		print(" > Deleted session file -",SESSION_ID)	
	except:
		pass
	
def Cleanup_Sessions():
	global DB
	print("CLEANUP SESSIONS AND ACL")
	DB.query("DELETE FROM `vmq_auth_acl` WHERE length(`client_id`) > 8")

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
			
def Create_Session(UID, OTP, CTR, IP):
	global DB,SERVER_SEED,MQTT_PORT,MQTT_HOST_IP
	# Create session user ACL for client
	HASH = SHA256.new()
	HASH.update((''.join([UID, OTP, str(CTR)])).encode())
	MSG_PWD = HASH.hexdigest()[:8]
	# Create session config for client
	HASH = SHA256.new()
	HASH.update((''.join([UID, str(time.time()), SERVER_SEED.hex()])).encode())
	SESSION_ID = HASH.hexdigest()[:8]	
	PUB_ACL = '[{"pattern":"up/%u/%c/#"}]'
	SUB_ACL = '[{"pattern":"dn/%u/%c/#"},{"pattern":"sdp_ctrl/all/#"}]'
	try:
		cursor = DB.query("SELECT * FROM `vmq_auth_acl` WHERE `client_id` = '"+OTP+"'")
		SESSION_CLIENT = cursor.fetchall()
		if SESSION_CLIENT == []:
			DB.query("INSERT INTO `vmq_auth_acl`(`mountpoint`, `client_id`, `username`, `password`, `publish_acl`, `subscribe_acl`, `session_ip`, `session_id`) VALUES ('','"+OTP+"','"+UID+"',password('"+MSG_PWD+"'),'"+PUB_ACL+"','"+SUB_ACL+"','"+IP+"','"+SESSION_ID+"')")
			print("ADDED NEW SESSION ACL - USER:%s, CLIENT:%s" %(UID,OTP))
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
	except Exception as e:
		print(str(e))
		return
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

		
def Validate_SPA(DATA, ADDR):
	global DB,SERVER_SEED,SERVER_SHARED_IV,SERVER_SHARED_KEY
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
	HASH.update(b''.join([REQ_UID,SERVER_SEED,USER_SPA_CTR]))
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
		HASH.update(b''.join([REQ_UID,SERVER_SEED,USER_SPA_CTR]))
		SERVER_OTP = bytes.fromhex(HASH.hexdigest()[:16])		
	print("SPA FROM %s VALIDATED" %(REQ_UID_HEX))
	Sync_Counter(REQ_UID_HEX, USER[0]["SPA_CTR"]+i)
	Create_Session(REQ_UID_HEX, REQ_OTP.hex(), USER[0]["SPA_CTR"]+i, ADDR[0])

def Initialize_Firewall_Rulles():
	Restore_Firewall()
	print("INITIALIZ SDP FIREWALL RULES")
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

def Monitor_Sessions(INTERVAL):
	while True:
		time.sleep(5)
		userlist = glob.glob(os.path.join("/home", "*"))
		if userlist == []:
			continue
		WHO = subprocess.check_output(["who", "-u"]).decode("utf-8")
		for d in userlist:
			if time.time()-os.path.getatime(d) < INTERVAL:
				continue
			USERNAME = d.replace("/home/","")
			if USERNAME not in WHO:
				Delete_User(USERNAME)
				Delete_Session(USERNAME[:16])

def Connect_DB(HOST, PORT, USER, PWD, DB):
	return mysql.connector.connect(host=HOST, port=PORT, user=USER, password=PWD, database=DB, autocommit=True)	

def on_connect(client, userdata, flags, rc):
	client.publish("sdp_ctrl/all", "CONNECTED", retain=True)
	client.subscribe("up/#")
	client.subscribe("gateway/#")
	print("CONNECTED TO MQTT SERVICE")
	
def on_disconnect(client, userdata, rc):
	print("MQTT SERVICE DISCONNECTED")
	client.LOOP_STOP()
		
def MQTT_LOOP(MQTT_HOST_IP, MQTT_PORT, SERVER_SEED):
	client = mqtt.Client(client_id="00001")
	client.username_pw_set("sdp_ctrl", password=SERVER_SEED)
	client.will_set("sdp_ctrl/all", payload="DISCONNECTED", retain=True)
	client.on_connect = on_connect
	client.on_disconnect = on_disconnect
	client.on_message = on_message
	while 1:
		try:
			print("CONNECTING TO SDP MQTT SERVICE ...")
			client.connect(MQTT_HOST_IP, int(MQTT_PORT), 5)
			client.loop_forever()
		except Exception as e:
			print("UNABLE TO CONNECT SDP MQTT SERVICE\n",str(e))
			time.sleep(2)

def on_message(client, userdata, msg):
	global DB
	TOPIC = msg.topic
	PAYLOAD = msg.payload.decode()
	print("[MQTT] "+ TOPIC+" : "+PAYLOAD)
	T = TOPIC.split('/')
	if T[0] == "up":
		USER = T[1] 
		CID = T[2]		
		if PAYLOAD == "CONNECTED":
			# Get session_id for the connection, send it to client
			cursor = DB.query("SELECT session_id,session_ip,RSA_PUB_KEY,AUTHORIZED_SVC FROM `vmq_auth_acl` JOIN `users` ON `vmq_auth_acl`.`username` = `users`.`UID` WHERE `vmq_auth_acl`.`username` = '"+USER+"' AND `vmq_auth_acl`.`client_id` = '"+CID+"'")
			# cursor = DB.query("SELECT * FROM `vmq_auth_acl` WHERE `username` = '"+USER+"' AND `client_id` = '"+CID+"'")
			SESSION_CLIENT = cursor.fetchone()
			# Increase user session counter by 1 upon session client connection
			DB.query("UPDATE `users` SET `SPA_CTR`=`SPA_CTR`+1 WHERE `UID` = '"+USER+"'")
			print("USER %s-%s AUTH OK, ESTABLISH mTLS CONNECTION" %(USER,CID))
			client.publish("dn/"+USER+"/"+CID+"/session_id", SESSION_CLIENT['session_id'])
			print("SEND SESSION ID TO GATEWAY")
			client.publish("sdp_ctrl/gateway/connection/open", json.dumps(SESSION_CLIENT))
		elif PAYLOAD == "DISCONNECTED":
			# Get session_id for the connection, send it to client
			cursor = DB.query("SELECT session_id,session_ip,RSA_PUB_KEY,AUTHORIZED_SVC FROM `vmq_auth_acl` JOIN `users` ON `vmq_auth_acl`.`username` = `users`.`UID` WHERE `vmq_auth_acl`.`username` = '"+USER+"' AND `vmq_auth_acl`.`client_id` = '"+CID+"'")
			# cursor = DB.query("SELECT * FROM `vmq_auth_acl` WHERE `username` = '"+USER+"' AND `client_id` = '"+CID+"'")
			SESSION_CLIENT = cursor.fetchone()
			del SESSION_CLIENT['AUTHORIZED_SVC']
			del SESSION_CLIENT['RSA_PUB_KEY']
			print("USER %s-%s DISCONNECTED, CLOSE mTLS CONNECTION" %(USER,CID))
			print("--> DELERE FIREWALL ENTRY ON GATEWAY")
			client.publish("sdp_ctrl/gateway/connection/close", json.dumps(SESSION_CLIENT))
			print("--> DELERE FROM SESSION RECORDS AND ACL")
			DB.query("DELETE FROM `vmq_auth_acl` WHERE `username`='"+USER+"' AND `client_id`='"+CID+"'")

			
			
			
				
	
	
# Main program	

print("Initialize server configurations")
with open('config','r') as f:
    CONFIG = json.loads(f.read())
SPA_PORT = int(CONFIG['SPA_PORT'])
SERVER_SHARED_KEY = bytes.fromhex(CONFIG['SERVER_SHARED_KEY'])
SERVER_SHARED_IV = bytes.fromhex(CONFIG['SERVER_SHARED_IV'])
SERVER_SEED = bytes.fromhex(CONFIG['SERVER_SEED'])
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

print("Initialize message client")
threading.Thread(target=MQTT_LOOP,args=(MQTT_HOST_IP,MQTT_PORT,SERVER_SEED.hex())).start()

print("Connecting to database")
DB = Database()

print("Initialize firewal rulls")	
Initialize_Firewall_Rulles()

print("Initialize sessions")
Cleanup_Sessions()

# print("Start session watchdog")
# threading.Thread(target=Monitor_Sessions,args=(5,)).start()
print("Start UDP server")
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCKET.bind(("", SPA_PORT))
while True:
	data, addr = SOCKET.recvfrom(32)
	threading.Thread(target=Validate_SPA,args=(data,addr)).start()
	
