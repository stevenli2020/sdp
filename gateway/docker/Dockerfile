# SDP PROJECT PoC Demo
FROM ubuntu:18.04
RUN apt update && apt install -y python3 python3-pip iptables net-tools iputils-ping nano curl sudo openssh-server
RUN pip3 install pycrypto && pip3 install mysql-connector-python && pip3 install paho-mqtt

RUN groupadd SDP

#COPY . /app
#RUN make /app
#CMD python /app/app.py