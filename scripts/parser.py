import pandas as pd
import os
from scapy.all import rdpcap, TCP, Raw, IP
import struct
import warnings
warnings.filterwarnings('ignore')

def parse_modbus_packet(payload):
    try:
        if len(payload) < 8:
            return None
        transaction_id = struct.unpack('>H', payload[0:2])[0]
        protocol_id = struct.unpack('>H', payload[2:4])[0]
        if protocol_id != 0:
            return None
        function_code = payload[7]
        return {
            'transaction_id': transaction_id,
            'function_code': function_code,
        }
    except:
        return None

def parse_pcap(filepath):
    records = []
    try:
        packets = rdpcap(filepath)
        for packet in packets:
            try:
                if TCP in packet and IP in packet:
                    if packet[TCP].dport == 502 or packet[TCP].sport == 502:
                        if Raw in packet:
                            payload = bytes(packet[Raw].load)
                            modbus = parse_modbus_packet(payload)
                            if modbus:
                                record = {
                                    'timestamp': float(packet.time),
                                    'src_ip': packet[IP].src,
                                    'dst_ip': packet[IP].dst,
                                    'length': len(packet),
                                    'function_code': modbus['function_code'],
                                    'transaction_id': modbus['transaction_id'],
                                }
                                records.append(record)
            except:
                continue
    except Exception as e:
        print(f"  Error: {e}")
    return pd.DataFrame(records)

def parse_all(data_folder):
    all_frames = []
    for filename in sorted(os.listdir(data_folder)):
        if filename.endswith('.pcap') or filename.endswith('.pcapng'):
            filepath = os.path.join(data_folder, filename)
            print(f"Parsing {filename}...")
            df = parse_pcap(filepath)
            if len(df) > 0:
                df['source_file'] = filename
                all_frames.append(df)
                print(f"  Found {len(df)} Modbus packets")
    if not all_frames:
        print("No Modbus packets found.")
        return pd.DataFrame()
    combined = pd.concat(all_frames, ignore_index=True)
    return combined

if __name__ == "__main__":
    df = parse_all('data/')
    df.to_csv('data/parsed_traffic.csv', index=False)
    print(f"\nDone. {len(df)} total Modbus packets parsed.")
    print(df.head(10))
