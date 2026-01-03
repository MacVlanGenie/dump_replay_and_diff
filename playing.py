import argparse
import socket
import json
import time

class playing:

    def __init__(self, json_file_path):
        self.found_field = None
        self.json_file_path = json_file_path

    def find_a_field(self, packet, keyword):
        for header in packet:
            if header == keyword:
#                print("GOT A BASTARD")
#                print(packet[header])
                self.found_field = packet[header]
            elif isinstance(packet[header], dict):
                playing.find_a_field(self, packet[header], keyword)
            else:
                continue
        return self.found_field

    def replay_traffic(self):
        with open(json_file_path, 'r') as file:
            data = json.load(file)

        for packet_data in data:
#            print(packet_data)
            packet = packet_data.get("packet", {})
            ip_src = playing.find_a_field(self, packet_data, 'ip.src')
#            import pdb; pdb.set_trace()
            ip_dst = playing.find_a_field(self, packet_data, 'ip.dst')
            src_port = int(playing.find_a_field(self, packet_data, 'tcp.srcport'))
            dst_port = int(playing.find_a_field(self, packet_data, 'tcp.dstport'))
            payload = playing.find_a_field(self, packet_data, 'tcp.payload').encode('utf-8')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#            if protocol == "TCP":
#                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#            elif protocol == "UDP":
#                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#            else:
#                print(f"Unsupported protocol: {protocol}")
#                continue

            try:
                sock.connect((ip_dst, dst_port))
                sock.sendall(payload)
                print(f"Packet sent: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
                response = sock.recv(1024).decode('utf-8')
                print(f"Answer: {response}")
            except Exception as e:
                print(f"Error: {ip_src}:{src_port} -> {ip_dst}:{dst_port}, message: {e}")
            finally:
                sock.close()
                time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keys to determine a path to JSONS of dumps.")
    parser.add_argument("--ignore", nargs='+', type=str, help="A path to dump in a JSON format")
    args = parser.parse_args()
    json_file_path = r"test.json"
    replay_init = playing(json_file_path)
    replay_init.replay_traffic()

