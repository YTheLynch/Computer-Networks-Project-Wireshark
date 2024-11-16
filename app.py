import os
from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from scapy.all import rdpcap
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)

@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory('/tmp', filename)

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
        img1, img2, img3, img4, img5, img6 = generate_plots(sorted_protocol_counts, sorted_ip_src_counts, sorted_ip_dst_counts, sorted_tcp_ports, sorted_udp_ports, syn_count, syn_ack_count)
        return render_template('results.html', plot1text=plot1text, plot2text=plot2text, plot3text=plot3text, plot4text=plot4text, plot5text=plot5text, plot6text=plot6text, img1 = img1, img2 = img2, img3 = img3, img4 = img4, img5 = img5, img6 = img6)


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
    buf1 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_protocol_counts], 7), showFirstNAddRest([i[1] for i in sorted_protocol_counts], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'])
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_protocol_counts], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.xlabel('Protocol Name')
    plt.ylabel('Packet Count')
    plt.title('Protocol - Wise Packet Counts')
    plt.savefig(buf1, format = 'png')
    buf1.seek(0)
    plt.close()

    buf2 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.pie(showFirstNAddRest([i[1] for i in sorted_ip_src_counts], 9), labels = showFirstNAppendOthers([str(i[0]) for i in sorted_ip_src_counts], 9), autopct='%1.1f%%',pctdistance=0.9)
    plt.legend()
    plt.title('Source IP Distribution')
    plt.savefig(buf2, format = 'png')
    buf2.seek(0)
    plt.close()

    buf3 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.pie(showFirstNAddRest([i[1] for i in sorted_ip_dst_counts], 9), labels = showFirstNAppendOthers([i[0] for i in sorted_ip_dst_counts], 9), autopct='%1.1f%%',pctdistance=0.9)
    plt.legend()
    plt.title('Destination IP Distribution')
    plt.savefig(buf3, format = 'png')
    buf3.seek(0)
    plt.close()


    buf4 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_tcp_ports], 7), showFirstNAddRest([i[1] for i in sorted_tcp_ports], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'], )
    plt.xlabel('TCP Port')
    plt.ylabel('Packet Count')
    plt.title('TCP Port - Wise Packet Counts')
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_tcp_ports], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.savefig(buf4, format = 'png')
    buf4.seek(0)
    plt.close()

    buf5 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.bar(showFirstNAppendOthers([str(i[0]) for i in sorted_udp_ports], 7), showFirstNAddRest([i[1] for i in sorted_udp_ports], 7), color=['blue', 'green', 'red', 'yellow', 'purple', 'brown'])
    plt.xlabel('UDP Port')
    plt.ylabel('Packet Count')
    plt.title('UDP Port - Wise Packet Counts')
    for i, value in enumerate(showFirstNAddRest([i[1] for i in sorted_udp_ports], 7)):
        plt.text(i, value + 0.5, str(value), ha='center', va='bottom')
    plt.savefig(buf5, format = 'png')
    buf5.seek(0)
    plt.close()

    buf6 = io.BytesIO()
    plt.figure(figsize=(18, 9.5))
    plt.hist([list(syn_count.keys()), list(syn_ack_count.keys())], weights = [list(syn_count.values()), list(syn_ack_count.values())], label = ['SYN count', 'SYN ACK count'])
    plt.legend()
    plt.savefig(buf6, format = 'png')
    buf6.seek(0)
    plt.close()


    img1_base64 = base64.b64encode(buf1.getvalue()).decode('utf-8')
    img2_base64 = base64.b64encode(buf2.getvalue()).decode('utf-8')
    img3_base64 = base64.b64encode(buf3.getvalue()).decode('utf-8')
    img4_base64 = base64.b64encode(buf4.getvalue()).decode('utf-8')
    img5_base64 = base64.b64encode(buf5.getvalue()).decode('utf-8')
    img6_base64 = base64.b64encode(buf6.getvalue()).decode('utf-8')

    buf1.close()
    buf2.close()
    buf3.close()
    buf4.close()
    buf5.close()
    buf6.close()

    return img1_base64, img2_base64, img3_base64, img4_base64, img5_base64, img6_base64

if __name__ == '__main__':
    app.run(debug=True)
