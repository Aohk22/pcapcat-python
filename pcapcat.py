import argparse
from scapy.all import Raw, rdpcap, sniff, TCP, IP


def parse_arguments():
    parser = argparse.ArgumentParser(description='pcapcat in Python using Scapy')
    parser.add_argument('-r', '--read', help='Path to PCAP file', required=True)
    parser.add_argument('-w', '--write', help='Output file for stream data')
    parser.add_argument('-d', '--dump', type=int, help='Index of connection to dump')
    parser.add_argument('-a', '--all', action='store_true', help='Show all TCP packets instead of just SYN')
    parser.add_argument('--version', action='version', version='pcapcat-python v0.1.0. Inspired by pcapcat by Kristinn Gudjonsson')
    return parser.parse_args()


def get_tcp_connections(pkts, only_syn=True) -> list:
    streams = []
    for pkt in pkts:
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            if only_syn:
                if tcp_layer.flags & 0b00000010:
                    streams.append(pkt)
            else:
                streams.append(pkt)
    return streams


def list_tcp_connections(pkts, only_syn=True):
    tcp_packets = get_tcp_connections(pkts, only_syn=only_syn)
    for i, pkt in enumerate(tcp_packets, 1):
        tcp = pkt[TCP]
        ip = pkt[IP]
        print(f'[{i}] TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}[{pkt.packet_number}]')
    return tcp_packets


def dump_stream(pkts, target_pkt, output_path):
    ip = target_pkt[IP]
    tcp = target_pkt[TCP]
    stream_data = b""
    for pkt in pkts:
        if IP in pkt and TCP in pkt:
            ip2 = pkt[IP]
            tcp2 = pkt[TCP]
            if (
                {ip.src, ip.dst} == {ip2.src, ip2.dst} and
                {tcp.sport, tcp.dport} == {tcp2.sport, tcp2.dport}
            ):
                if Raw in tcp2:
                    stream_data += bytes(tcp2[Raw].load)

    with open(output_path, 'wb') as file:
        file.write(stream_data)
    print(f"Dumped stream to {output_path=}")


def main():
    args = parse_arguments()

    try:
        pkts = rdpcap(args.read)
    except Exception as e:
        print(f"Failed to read PCAP: {e}")
        exit(1)

    for i, pkt in enumerate(pkts, 1):
        pkt.packet_number = i

    if args.dump is not None:
        if args.write is None:
            print(f"Output file must be specified with -w when dumping a stream")
            exit(1)

        connections = get_tcp_connections(pkts, only_syn=not args.all)
        if args.dump < 1 or args.dump > len(connections):
            print('Invalid index for dumping')
            exit(1)

        target_pkt = connections[args.dump - 1]
        dump_stream(pkts, target_pkt, args.write)
    else:
        list_tcp_connections(pkts, only_syn=not args.all)

if __name__ == '__main__':
    main()
