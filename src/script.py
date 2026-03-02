import pyshark
from collections import Counter


THRESHOLD = 50
connection_count = Counter()

def analyzer_packet(pkt):
    try:
        if hasattr(pkt, 'ip'):
            protocol = pkt.transport_layer
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            
            src_port = pkt[protocol].srcport
            dst_port = pkt[protocol].dstport
            
            connection_count[(src_ip, dst_port)] += 1

            print(f"[{protocol}] Source IP:{src_ip} and port:{src_port} ---> Destination IP:{dst_ip} and port:{dst_port}")
    except AttributeError:
        pass


capture = pyshark.FileCapture('discovery_scan_dcerpc_endpoint_mapper.pcapng')
capture.apply_on_packets(analyzer_packet, timeout=10)

for (src_ip, dst_port), count in connection_count.items():
    if int(dst_port) < 1024 and count > THRESHOLD:
        print(f"[ALERT] IP {src_ip} sent {count} packets to port {dst_port}")