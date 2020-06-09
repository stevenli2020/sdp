#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json,sys,socket,threading,subprocess,time,os.path,atexit,os,glob
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def At_Exit_Cleanup_Sessions():
	filelist = glob.glob(os.path.join("sessions", "*"))
	if filelist == []:
		print("\nBye")
		return
	print("Clean up session files:")
	for f in filelist:
		os.remove(f)
		print(" > Deleted session -",f)
	print("\nBye")

atexit.register(At_Exit_Cleanup_Sessions) 
	
def Create_SSL_Session(UID, CONF, IP):
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

def Sync_Counter(UID,CTR):
	with open('users','r+') as f:
		USERS = json.loads(f.read())
		USERS[UID]["SPA_CTR"] = CTR + 1
		f.seek(0)
		f.write(json.dumps(USERS,indent=2))
		f.truncate()

def Local_Firewall_P60022_Open_10s(IP):
	# iptables -I INPUT -p tcp -s 1.1.1.1 --dport 60022 -j ACCEPT
	print("Firewall add tcp/60022 for", IP)
	subprocess.check_output(["iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", IP, "--dport", "60022", "-j", "ACCEPT"])
	time.sleep(10)
	subprocess.check_output(["iptables", "-D", "INPUT", "-p", "tcp", "-s", IP, "--dport", "60022", "-j", "ACCEPT"])
	print("Firewall delete tcp/60022 for", IP)
		
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
	Create_SSL_Session(REQ_UID_HEX, USERS[REQ_UID_HEX], ADDR[0])
	Local_Firewall_P60022_Open_10s(ADDR[0])

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

	
	
	
	
	
# Main program	
print("Initialize Firewal rulls")	
Initialize_Firewall_Rulles()
print("Initialize server configurations")
with open('config','r') as f:
    CONFIG = json.loads(f.read())
SPA_PORT = int(CONFIG['SPA_PORT'])
SERVER_SHARED_KEY = bytes.fromhex(CONFIG['SERVER_SHARED_KEY'])
SERVER_SHARED_IV = bytes.fromhex(CONFIG['SERVER_SHARED_IV'])
SERVER_SEED = bytes.fromhex(CONFIG['SERVER_SEED'])
print("Start UDP server")
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCKET.bind(("", SPA_PORT))
while True:
	data, addr = SOCKET.recvfrom(1024)
	threading.Thread(target=Validate_SPA,args=(data,addr)).start()
	
