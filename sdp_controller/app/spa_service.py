#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json,sys,socket,threading,subprocess,time,os.path,atexit,os,glob,shutil
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def At_Exit():
	Cleanup_Sessions()
	Restore_Firewall()
	print("\nBye")

atexit.register(At_Exit) 

def Disconnect_User(UID):
	print("Disconnect user:",UID)
	try:
	#pkill -KILL -u [UID]
		subprocess.check_output(["pkill", "-KILL", "-u", UID])
	except:
		pass
	Delete_User(UID)
	Delete_Session(UID)
	
	
def Delete_User(UID):
	print("Delete user:",UID)
	try:
		#userdel -f [UID]
		subprocess.check_output(["userdel", "-f", UID])
		shutil.rmtree("/home/"+UID)
		print(" > Deleted session user -",UID)
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
	userlist = glob.glob(os.path.join("/home", "*"))
	if userlist != []:
		print("Cleaning up session users:")
		for d in userlist:
			USERNAME = d.replace("/home/","")
			Disconnect_User(USERNAME)


	
def Restore_Firewall():
	#iptables -F INPUT
	subprocess.check_output(["iptables", "-F", "INPUT"])
		
def Create_SSL_Session(UID, OTP, CONF, IP):
	global SERVER_SEED
	print("Create SSL session configuration for", UID)
	SESSION = {}
	SESSION["SERVICES_AUTHORIZED"] = CONF["SERVICES"]
	HASH = SHA256.new()
	HASH.update((''.join([UID, str(time.time()), SERVER_SEED.hex()])).encode())
	SESSION['SESSION_ID'] = HASH.hexdigest()[:8]
	SESSION['SESSION_USER'] = UID+"-"+SESSION['SESSION_ID']
	SESSION['SESSION_USER_IP'] = IP
	with open('sessions/'+UID,'w+') as f:
		f.write(json.dumps(SESSION,indent=2))
		f.truncate()
	# add session user: useradd -m username
	print("Create session user", UID+OTP)
	subprocess.check_output(["useradd", "-m", UID+OTP])
	os.makedirs('/home/'+UID+OTP+'/.ssh') 
	with open('/home/'+UID+OTP+'/.ssh/authorized_keys','w+') as f:
		f.write(CONF['RSA_PUB_KEY'])

def Sync_Counter(UID,CTR):
	with open('users','r+') as f:
		USERS = json.loads(f.read())
		USERS[UID]["SPA_CTR"] = CTR + 1
		f.seek(0)
		f.write(json.dumps(USERS,indent=2))
		f.truncate()

def Local_Firewall_P22_Open_10s(IP):
	# iptables -I INPUT -p tcp -s 1.1.1.1 --dport 22 -j ACCEPT
	print("Firewall add tcp/22 for", IP)
	subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", IP, "--dport", "22", "-j", "ACCEPT"])
	time.sleep(10)
	subprocess.check_output(["iptables", "-D", "INPUT", "-p", "tcp", "-s", IP, "--dport", "22", "-j", "ACCEPT"])
	print("Firewall delete tcp/22 for", IP)
		
def Validate_SPA(DATA, ADDR):
	global SERVER_SEED,SERVER_SHARED_IV,SERVER_SHARED_KEY
	if len(DATA) != 32: # check if packet size is 32, which is the default lenth for our SPA format 
		return
	CIPHER_OBJ = AES.new(SERVER_SHARED_KEY, AES.MODE_CBC, SERVER_SHARED_IV)
	DEC_DATA = CIPHER_OBJ.decrypt(DATA)
	# print("R_DATA="+DEC_DATA.hex())
	# return
	REQ_UID = DEC_DATA[0:8]
	REQ_UID_HEX = REQ_UID.hex()
	if os.path.isfile("sessions/"+REQ_UID_HEX): # check if session has already been established
		return
	REQ_OTP = DEC_DATA[8:16]
	REQ_GMAC = DEC_DATA[16:]
	with open('users','r') as f:
		USERS = json.loads(f.read())
	if not REQ_UID_HEX in USERS:
		return
	USER_SPA_CTR = bytes.fromhex(("0000000000000000"+hex(USERS[REQ_UID_HEX]["SPA_CTR"])[2:])[-16:])
	HASH = SHA256.new()
	HASH.update(b''.join([REQ_UID,SERVER_SEED,USER_SPA_CTR]))
	SERVER_OTP = bytes.fromhex(HASH.hexdigest()[:16])
	# print("S_OTP="+SERVER_OTP.hex())
	# print("R_OTP="+REQ_OTP.hex())
	i = 0
	while SERVER_OTP != REQ_OTP:
		i = i + 1
		if i == 4:
			return	
		USER_SPA_CTR = bytes.fromhex(("0000000000000000"+hex(USERS[REQ_UID_HEX]["SPA_CTR"]+i)[2:])[-16:])
		HASH = SHA256.new()
		HASH.update(b''.join([REQ_UID,SERVER_SEED,USER_SPA_CTR]))
		SERVER_OTP = bytes.fromhex(HASH.hexdigest()[:16])		
	#Sync_Counter(REQ_UID_HEX, USERS[REQ_UID_HEX]["SPA_CTR"]+i)
	print("SPA from %s OK" %(REQ_UID_HEX))
	Create_SSL_Session(REQ_UID_HEX, REQ_OTP.hex(), USERS[REQ_UID_HEX], ADDR[0])
	Local_Firewall_P22_Open_10s(ADDR[0])

def Initialize_Firewall_Rulles():
	#iptables -P INPUT DROP 
	subprocess.check_output(["iptables", "-P", "INPUT", "DROP"])
	#iptables -P FORWARD DROP 
	subprocess.check_output(["iptables", "-P", "FORWARD", "DROP"])
	#iptables -A INPUT -p udp --dport 60001 -j ACCEPT
	subprocess.check_output(["iptables", "-A", "INPUT", "-p", "udp", "--dport", "60001", "-j", "ACCEPT"])
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

# Main program	
print("Initialize Firewal rulls")	
Initialize_Firewall_Rulles()
print("Initialize Sessions")
Cleanup_Sessions()
print("Initialize server configurations")
with open('config','r') as f:
    CONFIG = json.loads(f.read())
SPA_PORT = int(CONFIG['SPA_PORT'])
SERVER_SHARED_KEY = bytes.fromhex(CONFIG['SERVER_SHARED_KEY'])
SERVER_SHARED_IV = bytes.fromhex(CONFIG['SERVER_SHARED_IV'])
SERVER_SEED = bytes.fromhex(CONFIG['SERVER_SEED'])
print("Start session watchdog")
threading.Thread(target=Monitor_Sessions,args=(5,)).start()
print("Start UDP server")
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCKET.bind(("", SPA_PORT))
while True:
	data, addr = SOCKET.recvfrom(1024)
	threading.Thread(target=Validate_SPA,args=(data,addr)).start()
	
