from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
import random
import os

# Synthetic MAC addresses (locally administered, unicast)
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.168.1.100"
SERVER_IP = "192.168.1.10"
CLIENT_PORT_1 = random.randint(49152, 65535)
CLIENT_PORT_2 = random.randint(49152, 65535)

packets = []

def tcp_handshake(client_ip, server_ip, client_port, server_port, start_seq=1000, start_ack=2000):
    """Create TCP 3-way handshake with Ethernet headers."""
    syn = Ether(src=CLIENT_MAC, dst=SERVER_MAC)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=start_seq)
    syn_ack = Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=start_ack, ack=start_seq+1)
    ack = Ether(src=CLIENT_MAC, dst=SERVER_MAC)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=start_seq+1, ack=start_ack+1)
    return [syn, syn_ack, ack], start_seq+1, start_ack+1

def tcp_data(client_ip, server_ip, client_port, server_port, data, seq, ack, from_client=True):
    """Create TCP data packet with Ethernet headers."""
    if from_client:
        pkt = Ether(src=CLIENT_MAC, dst=SERVER_MAC)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=seq, ack=ack)/Raw(load=data)
        return pkt, seq + len(data), ack
    else:
        pkt = Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=ack, ack=seq)/Raw(load=data)
        return pkt, seq, ack + len(data)

def tcp_fin(client_ip, server_ip, client_port, server_port, seq, ack):
    """Create TCP FIN sequence with Ethernet headers."""
    fin1 = Ether(src=CLIENT_MAC, dst=SERVER_MAC)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="FA", seq=seq, ack=ack)
    fin_ack = Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="FA", seq=ack, ack=seq+1)
    final_ack = Ether(src=CLIENT_MAC, dst=SERVER_MAC)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=seq+1, ack=ack+1)
    return [fin1, fin_ack, final_ack]

print("Creating SMTP conversation on port 25...")

handshake_pkts, c_seq, s_seq = tcp_handshake(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25)
packets.extend(handshake_pkts)

smtp_greeting = b"220 mail.example.test ESMTP SecureMailScope Test Server\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, smtp_greeting, c_seq, s_seq, from_client=False)
packets.append(pkt)

ehlo = b"EHLO client.example.test\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, ehlo, c_seq, s_seq, from_client=True)
packets.append(pkt)

ehlo_response = b"250-mail.example.test Hello client.example.test\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250 PIPELINING\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, ehlo_response, c_seq, s_seq, from_client=False)
packets.append(pkt)

mail_from = b"MAIL FROM:<sender@example.test>\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, mail_from, c_seq, s_seq, from_client=True)
packets.append(pkt)

mail_ok = b"250 2.1.0 Ok\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, mail_ok, c_seq, s_seq, from_client=False)
packets.append(pkt)

rcpt_to = b"RCPT TO:<recipient@example.test>\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, rcpt_to, c_seq, s_seq, from_client=True)
packets.append(pkt)

rcpt_ok = b"250 2.1.5 Ok\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, rcpt_ok, c_seq, s_seq, from_client=False)
packets.append(pkt)

data_cmd = b"DATA\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, data_cmd, c_seq, s_seq, from_client=True)
packets.append(pkt)

data_ready = b"354 End data with <CR><LF>.<CR><LF>\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, data_ready, c_seq, s_seq, from_client=False)
packets.append(pkt)

email_content = b"From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: Test Email - SYNTHETIC FIXTURE\r\nDate: Mon, 21 Sep 2026 12:00:00 +0000\r\n\r\nThis is a synthetic test email for SecureMailScope demo.\r\n.\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, email_content, c_seq, s_seq, from_client=True)
packets.append(pkt)

msg_ok = b"250 2.0.0 Ok: queued as SYNTHETIC123\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, msg_ok, c_seq, s_seq, from_client=False)
packets.append(pkt)

quit_cmd = b"QUIT\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, quit_cmd, c_seq, s_seq, from_client=True)
packets.append(pkt)

bye = b"221 2.0.0 Bye\r\n"
pkt, c_seq, s_seq = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, bye, c_seq, s_seq, from_client=False)
packets.append(pkt)

fin_pkts = tcp_fin(CLIENT_IP, SERVER_IP, CLIENT_PORT_1, 25, c_seq, s_seq)
packets.extend(fin_pkts)

print("Creating SMTP submission conversation on port 587...")

handshake_pkts2, c_seq2, s_seq2 = tcp_handshake(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, start_seq=5000, start_ack=6000)
packets.extend(handshake_pkts2)

smtp_greeting2 = b"220 submission.example.test ESMTP SecureMailScope Submission Server\r\n"
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, smtp_greeting2, c_seq2, s_seq2, from_client=False)
packets.append(pkt)

ehlo2 = b"EHLO client.example.test\r\n"
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, ehlo2, c_seq2, s_seq2, from_client=True)
packets.append(pkt)

ehlo_response2 = b"250-submission.example.test\r\n250-SIZE 52428800\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 PIPELINING\r\n"
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, ehlo_response2, c_seq2, s_seq2, from_client=False)
packets.append(pkt)

starttls = b"STARTTLS\r\n"
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, starttls, c_seq2, s_seq2, from_client=True)
packets.append(pkt)

tls_ready = b"220 2.0.0 Ready to start TLS\r\n"
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, tls_ready, c_seq2, s_seq2, from_client=False)
packets.append(pkt)

tls_client_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, tls_client_hello, c_seq2, s_seq2, from_client=True)
packets.append(pkt)

tls_server_hello = bytes([0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00])
pkt, c_seq2, s_seq2 = tcp_data(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, tls_server_hello, c_seq2, s_seq2, from_client=False)
packets.append(pkt)

fin_pkts2 = tcp_fin(CLIENT_IP, SERVER_IP, CLIENT_PORT_2, 587, c_seq2, s_seq2)
packets.extend(fin_pkts2)

output_path = "/app/tests/fixtures/smtp_starttls_demo.pcap"
wrpcap(output_path, packets)

print(f"Created {output_path} with {len(packets)} packets")
print("  - Connection 1: Port 25 (SMTP) - STARTTLS advertised but NOT used")
print("  - Connection 2: Port 587 (Submission) - STARTTLS negotiated")
