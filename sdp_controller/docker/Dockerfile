# SDP PROJECT PoC Demo
FROM ubuntu:20.04
RUN apt update && apt install -y python3 python3-pip iptables net-tools iputils-ping 
RUN pip3 install pycrypto && pip3 install paramiko
RUN iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -A INPUT -p udp --dport 60001 -j ACCEPT && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT && iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#COPY . /app
#RUN make /app
#CMD python /app/app.py