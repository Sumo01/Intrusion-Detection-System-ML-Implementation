import pyshark
import pandas as pd

def capture_packets():
    iface_name = 'Wi-Fi'
    filter_string = 'port 80'
    capture = pyshark.LiveCapture(
        interface=iface_name,
        bpf_filter=filter_string
    )
    capture.sniff(timeout=5, packet_count=10)
    # Create an empty list to store the extracted fields
    packet_fields = []
    # Loop through each packet and extract the required fields
    for packet in capture:
        packet_dict = {}
        packet_dict['protocol_type'] = packet.ip.proto
        packet_dict['service'] = packet.tcp.dstport
        packet_dict['flag'] = packet.tcp.flags
        packet_dict['src_bytesdst'] = packet.length
        packet_dict['bytes'] = packet.length
        packet_dict['logged_in'] = packet.tcp.flags_push
        packet_dict['count'] = packet.tcp.analysis_ack_rtt_count
        packet_dict['srv_count'] = packet.tcp.analysis_duplicate_ack_count
        packet_dict['serror_rate'] = packet.tcp.analysis_rto_count
        packet_dict['srv_rerror_rate'] = packet.tcp.analysis_rto_min
        packet_dict['rerror_rate'] = packet.tcp.analysis_rto_max
        packet_dict['srv_rerror_rate.1'] = packet.tcp.analysis_rto_avg
        packet_dict['same_srv_rate'] = packet.tcp.analysis_bytes_in_flight
        packet_dict['diff_srv_rate'] = packet.tcp.analysis_push_bytes_sent
        packet_dict['srv_diff_host_rate'] = packet.tcp.analysis_bytes_acked
        packet_dict['dst_host_count'] = packet.tcp.analysis_acks_0
        packet_dict['dst_host_srv_count'] = packet.tcp.analysis_packets_out
        packet_dict['dst_host_same_srv_rate'] = packet.tcp.analysis_packets_in
        packet_dict['dst_host_diff_srv_rate'] = packet.tcp.analysis_duplicate_bytes
        packet_dict['dst_host_same_src_port_rate'] = packet.tcp.analysis_retransmitted_bytes
        packet_dict['dst_host_srv_diff_host_rate'] = packet.tcp.analysis_out_of_order
        packet_dict['dst_host_serror_rate'] = packet.tcp.analysis_window_full
        packet_dict['dst_host_srv_serror_rate'] = packet.tcp.analysis_window_full
        packet_dict['dst_host_rerror_rate'] = packet.tcp.analysis_fast_retransmission
        packet_dict['dst_host_srv_rerror_rate'] = packet.tcp.analysis_bytes_retrans
        
        packet_fields.append(packet_dict)

        # Convert the list of dictionaries into a pandas dataframe
        df = pd.DataFrame(packet_fields)

    # Print the first few rows of the dataframe
    print(df.head())

            

