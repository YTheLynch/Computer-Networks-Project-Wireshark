import os
from flask import Flask, request, render_template, redirect, url_for
from scapy.all import rdpcap
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

app = Flask(__name__)

if not os.path.exists('static'):
    os.makedirs('static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))
    if file:
        plot1text, plot2text, plot3text, plot4text, plot5text, plot6text, sorted_protocol_counts, sorted_ip_src_counts, sorted_ip_dst_counts, sorted_tcp_ports, sorted_udp_ports, syn_count, syn_ack_count = analyze_pcap(file)
        generate_plots(sorted_protocol_counts, sorted_ip_src_counts, sorted_ip_dst_counts, sorted_tcp_ports, sorted_udp_ports, syn_count, syn_ack_count)
        return render_template('results.html', plot1text=plot1text, plot2text=plot2text, plot3text=plot3text, plot4text=plot4text, plot5text=plot5text, plot6text=plot6text)


def showFirstNAddRest(arr, n):
    first = arr[:n]
    first.append(sum(arr[n:]))
    return first

def showFirstNAppendOthers(arr, n):
    first = arr[:n]
    first.append("Others")
    return first

def analyze_pcap(file):
    packets = rdpcap(file)
    
    protocol_counts = Counter()
    syn_count = Counter()
    syn_ack_count = Counter()

    for packet in packets:
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            tcp_layer = packet['TCP']
            
            if tcp_layer.flags == 'S':
                syn_count[src_ip] += 1
            
            elif tcp_layer.flags == 'SA':
                syn_ack_count[dst_ip] += 1

        for layer in packet.layers():
            protocol_name = layer.__name__  
            protocol_counts[protocol_name] += 1

    sorted_protocol_counts = sorted(protocol_counts.items(), key = lambda x: x[1], reverse = True)

    ip_src_counts = Counter(packet['IP'].src for packet in packets if packet.haslayer('IP'))
    ip_dst_counts = Counter(packet['IP'].dst for packet in packets if packet.haslayer('IP'))

    sorted_ip_src_counts = sorted(ip_src_counts.items(), key = lambda x: x[1], reverse = True)
    sorted_ip_dst_counts = sorted(ip_dst_counts.items(), key = lambda x: x[1], reverse = True)

    tcp_ports = Counter(packet['TCP'].dport for packet in packets if packet.haslayer('TCP'))
    udp_ports = Counter(packet['UDP'].dport for packet in packets if packet.haslayer('UDP'))

    sorted_tcp_ports = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)
    sorted_udp_ports = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)

    plot1text = "Protocol Counts:-\n" + ', '.join(f"{i[0]}: {i[1]}" for i in sorted_protocol_counts)
    plot2text = "Source IP Distribution:-\n" + ', '.join(f"{i[0]}: {i[1]}" for i in sorted_ip_src_counts)
    plot3text = "Destination IP Distribution:-\n" + ', '.join(f"{i[0]}: {i[1]}" for i in sorted_ip_dst_counts)
    plot4text = "TCP Port Wise Packet Counts:-\n" + ', '.join(f"Port {i[0]}: {i[1]} packets" for i in sorted_tcp_ports)
    plot5text = "UDP Port Wise Packet Counts:-\n" + ', '.join(f"Port {i[0]}: {i[1]} packets" for i in sorted_udp_ports)
    plot6text = "SYN Packet Count per IP:-\n" + ', '.join(f"{i[0]}: {i[1]}" for i in syn_count.items())
    plot6text += "\n\nSYN ACK Packet Count per IP:-\n" + ', '.join(f"{i[0]}: {i[1]}" for i in syn_ack_count.items())

    return plot1text, plot2text, plot3text, plot4text, plot5text, plot6text, sorted_protocol_counts, sorted_ip_src_counts, sorted_ip_dst_counts, sorted_tcp_ports, sorted_udp_ports, syn_count, syn_ack_count

def generate_plots(sorted_protocol_counts, sorted_ip_src_counts, sorted_ip_dst_counts, sorted_tcp_ports, sorted_udp_ports, syn_count, syn_ack_count):

    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_protocol_counts], 7), showFirstNAddRest([i[1] for i in sorted_protocol_counts], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'])
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_protocol_counts], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.xlabel('Protocol Name')
    plt.ylabel('Packet Count')
    plt.title('Protocol - Wise Packet Counts')
    plt.savefig(os.path.join('static', 'plot1.png'))
    plt.close()

    plt.figure(figsize=(18, 9.5))
    plt.pie(showFirstNAddRest([i[1] for i in sorted_ip_src_counts], 9), labels = showFirstNAppendOthers([str(i[0]) for i in sorted_ip_src_counts], 9), autopct='%1.1f%%',pctdistance=0.9)
    plt.legend()
    plt.title('Source IP Distribution')
    plt.savefig(os.path.join('static', 'plot2.png'))
    plt.close()

    plt.figure(figsize=(18, 9.5))
    plt.pie(showFirstNAddRest([i[1] for i in sorted_ip_dst_counts], 9), labels = showFirstNAppendOthers([i[0] for i in sorted_ip_dst_counts], 9), autopct='%1.1f%%',pctdistance=0.9)
    plt.legend()
    plt.title('Destination IP Distribution')
    plt.savefig(os.path.join('static', 'plot3.png'))
    plt.close()

    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_tcp_ports], 7), showFirstNAddRest([i[1] for i in sorted_tcp_ports], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'], )
    plt.xlabel('TCP Port')
    plt.ylabel('Packet Count')
    plt.title('TCP Port - Wise Packet Counts')
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_tcp_ports], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.savefig(os.path.join('static', 'plot4.png'))
    plt.close()

    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_udp_ports], 7), showFirstNAddRest([i[1] for i in sorted_udp_ports], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'])
    plt.xlabel('UDP Port')
    plt.ylabel('Packet Count')
    plt.title('UDP Port - Wise Packet Counts')
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_udp_ports], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.savefig(os.path.join('static', 'plot5.png'))
    plt.close()

    plt.figure(figsize=(18, 9.5))
    plt.hist([list(syn_count.keys()), list(syn_ack_count.keys())], weights = [list(syn_count.values()), list(syn_ack_count.values())], label = ['SYN count', 'SYN ACK count'])
    plt.legend()
    plt.savefig(os.path.join('static', 'plot6.png'))
    plt.close()

if __name__ == '__main__':
    app.run(debug=True)
