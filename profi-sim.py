import os, time
import yaml
from scapy.all import *
from scapy.layers.l2 import Ether
import threading
from tabulate import tabulate

### Defaults

controller_stats = {
    "rt_sent": 0,
    "rt_ack": 0,
    "pncc_sent": 0,
    "pncc_recv": 0,
    "dcp_sent": 0,
    "dcp_recv": 0,
    "alarm_recv": 0
}

device_stats = {
    "rt_recv": 0,
    "rt_ack": 0,
    "dcp_sent": 0,
    "dcp_recv": 0,
    "alarm_sent": 0,
    "pncc_sent": 0,
    "pncc_recv": 0
}


lock = threading.Lock()

##  View Function
def update_display(pn_data, this_device_role):
    for item in pn_data['devices']:
        if item['this'] == True:
            this_device=item
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print ("Device Name: {}".format(this_device['name']))
            print ("Role: {}".format(this_device['role']))
            print ("Mac: {}".format(this_device['mac']))
            print ("ip: {}\n".format(this_device['ip']))

            table_data = []

            with lock:
                if this_device_role=="controller":
                    for item in pn_data['devices']:
                        if item['role'] != "controller":
                            table_data.append([
                            item['name'],
                            item['mac'],
                            item['ip'],
                            item['stats']['rt_sent'],
                            item['stats']['rt_ack'],
                            item['stats']['pncc_sent'],
                            item['stats']['pncc_recv'],
                            item['stats']['dcp_sent'],
                            item['stats']['dcp_recv'],
                            item['stats']['alarm_recv']
                            ])

                    print(tabulate(table_data, headers=["Device Name", "MAC", "IP", "RT Sent", "RT Ack", "PNCC Sent", "PNCC Received", "DCP Sent", "DCP Received", "Alarms Received"], tablefmt="grid"))
                else:
                    for item in pn_data['devices']:
                        if item['role'] == "controller":
                            table_data.append([
                            item['name'],
                            item['mac'],
                            item['ip'],
                            item['stats']['rt_recv'],
                            item['stats']['rt_ack'],
                            item['stats']['dcp_sent'],
                            item['stats']['dcp_recv'],
                            item['stats']['pncc_sent'],
                            item['stats']['pncc_recv'],
                            item['stats']['alarm_sent']
                            ])

                    print(tabulate(table_data, headers=["Device Name", "MAC", "IP", "RT Received", "RT Ack", "DCP Received", "DCP Sent", "PNCC Received", "PNCC Sent", "Alarms Sent"], tablefmt="grid"))

                time.sleep(0.5)
    except KeyboardInterrupt:
        print("Exiting")

### Controller Functionality ###            

## Controller Send Packets
def ctrl_send_rt_messages():
    while True:
        for item in pn_data['devices']:
            if item['role'] !='controller':
                sendp(Ether(dst=item['mac'], type=pn_data['protocols']['pn_rt']['pn_rt_ether'])/Dot1Q(vlan=0,prio=pn_data['protocols']['pn_rt']['pn_rt_cos'])/Raw(load="RT_L2_Ctrl_to_Devices"), iface=item['iface'], verbose=0)
                
                with lock:
                    item['stats']['rt_sent'] += 1
        time.sleep(pn_data['protocols']['pn_rt']['pn_rt_timer'])

def ctrl_send_pncc_messages():
    while True:
        for item in pn_data['devices']:
            if item['role'] !='controller':
                send(IP(dst=item['ip'])/UDP(dport=pn_data['protocols']['pn_cc']['pn_cc_port'], sport=pn_data['protocols']['pn_cc']['pn_cc_port'])/Raw(load="PNCC_UDP_Ctrl_to_Devices"), iface=item['iface'], verbose=0)
                with lock:
                    item['stats']['pncc_sent'] += 1
        time.sleep(pn_data['protocols']['pn_cc']['pn_cc_timer'])

def ctrl_send_dcp_messages():
    while True:
        for item in pn_data['devices']:
            if item['role'] !='controller':
                sendp(Ether(dst=pn_data['protocols']['pn_dcp']['pn_dcp_bcast'])/Raw(load="DCP_Bcast_Discovery_Ctrl_to_Devices"), verbose=0)
                with lock:
                    item['stats']['dcp_sent'] += 1
        time.sleep(10)

## Controller Receive Packets

def ctrl_packet_sniffer():
    sniff(prn=ctrl_process_recv_traffic, store=False)

def ctrl_process_recv_traffic(packet):
    if packet.haslayer(Ether) and packet.type == pn_data['protocols']['pn_rt']['pn_rt_ether']:
        if Raw in packet:
            if "Alarm_Device_to_Ctrl" in packet[Raw].load.decode(errors='ignore'):
                with lock:
                    for item in pn_data['devices']:
                        if item['mac'] == packet.src:
                            item['stats']['alarm_recv'] += 1
            elif "RT_L2_Ack_Device_to_Ctrl" in packet[Raw].load.decode(errors='ignore'):
                with lock:
                    for item in pn_data['devices']:
                        if item['mac'] == packet.src:
                            item['stats']['rt_ack'] += 1
            elif "DCP_Bcast_Discovery_Ack_Device_to_Ctrl" in packet[Raw].load.decode(errors='ignore'):
                    with lock:
                        for item in pn_data['devices']:
                            if item['mac'] == packet.src:
                                item['stats']['dcp_recv'] += 1

    elif packet.haslayer(UDP) and packet[UDP].dport == pn_data['protocols']['pn_cc']['pn_cc_port']:
        if Raw in packet:
            if "PNCC_UDP_Device_to_Ctrl" in packet[Raw].load.decode(errors='ignore'):
                with lock:
                    for item in pn_data['devices']:
                        if item['ip'] == packet[IP].src:
                            item['stats']['pncc_recv'] += 1


### IO Device functionality ###

## Device Send Packets

def device_send_alarm_messages():
    while True:
        for item in pn_data['devices']:
            if item['role'] =='controller':
                sendp(Ether(dst=item['mac'], type=pn_data['protocols']['pn_rt']['pn_rt_ether'])/Dot1Q(vlan=0,prio=pn_data['protocols']['pn_rt']['pn_rt_cos'])/Raw(load="Alarm_Device_to_Ctrl"), iface=item['iface'], verbose=0)
                with lock:
                    item['stats']['alarm_sent'] += 1
        time.sleep(10)

def device_packet_sniffer():
    sniff(prn=device_process_recv_traffic, store=False)

def device_process_recv_traffic(packet):
    if packet.haslayer(Ether) and packet.type == pn_data['protocols']['pn_rt']['pn_rt_ether']:
        if Raw in packet:
            if "RT_L2_Ctrl_to_Devices" in packet[Raw].load.decode(errors='ignore'):
                with lock:
                    for item in pn_data['devices']:
                        if item['mac'] == packet.src:
                            item['stats']['rt_recv'] += 1
                            sendp(Ether(dst=item['mac'], type=pn_data['protocols']['pn_rt']['pn_rt_ether'])/Dot1Q(vlan=0,prio=pn_data['protocols']['pn_rt']['pn_rt_cos'])/Raw(load="RT_L2_Ack_Device_to_Ctrl"), iface=item['iface'], verbose=0)
                            item['stats']['rt_ack'] += 1

    elif packet.haslayer(UDP) and packet[UDP].dport == pn_data['protocols']['pn_cc']['pn_cc_port']:
        if Raw in packet:
            if "PNCC_UDP_Ctrl_to_Devices" in packet[Raw].load.decode():
                with lock:
                    for item in pn_data['devices']:
                        if item['ip'] == packet[IP].src:
                            item['stats']['pncc_recv'] += 1
                            send(IP(dst=item['ip'])/UDP(dport=pn_data['protocols']['pn_cc']['pn_cc_port'])/Raw(load="PNCC_UDP_Device_to_Ctrl"), iface=item['iface'], verbose=0)
                            item['stats']['pncc_sent'] += 1

    elif packet.haslayer(Ether) and packet[Ether].dst.lower() == pn_data['protocols']['pn_dcp']['pn_dcp_bcast'].lower():
        if Raw in packet:
            if "DCP_Bcast_Discovery_Ctrl_to_Devices" in packet[Raw].load.decode(errors='ignore'):
                with lock:
                    for item in pn_data['devices']:
                        if item['mac'] == packet.src:
                            item['stats']['dcp_recv'] += 1
                            sendp(Ether(dst=item['mac'], type=pn_data['protocols']['pn_rt']['pn_rt_ether'])/Raw(load="DCP_Bcast_Discovery_Ack_Device_to_Ctrl"), iface=item['iface'], verbose=0)
                            item['stats']['dcp_sent'] += 1


## Load YAML Data
def load_device_data():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("- Loading devices.yaml file ..... ")
        time.sleep(2)
        try:
            with open('devices.yaml', 'r') as file:
                data = yaml.load(file, Loader=yaml.FullLoader)
                time.sleep(1)
            break
        except FileNotFoundError:
            print("- File not found. Please ensure devices.yaml is in the same directory.")
            time.sleep(2)

        except yaml.YAMLError as e:
            print("- Error reading YAML file:", e)
            time.sleep(2)

    return data

if __name__ == "__main__":

    pn_data=load_device_data()
    
    
    for item in pn_data['devices']:
        if item['this'] == True and item['role']=='controller':
            this_device_role ="controller"
            for item in pn_data['devices']:
                if item['role']!='controller':
                    item['stats'] = controller_stats.copy()

        elif item['this'] == True and item['role']=='device':
            this_device_role ="device"
            for item in pn_data['devices']:
                if item['role']=='controller':
                    item['stats'] = device_stats.copy()

    display_thread = threading.Thread(target=update_display, args=(pn_data, this_device_role,))

    if this_device_role == "controller":

        ctrl_sent_rt_thread = threading.Thread(target=ctrl_send_rt_messages)
        ctrl_sent_pncc_thread= threading.Thread(target=ctrl_send_pncc_messages)
        ctrl_sent_dcp_thread= threading.Thread(target=ctrl_send_dcp_messages)
        ctrl_listen_thread = threading.Thread(target=ctrl_packet_sniffer)

        display_thread.start()
        ctrl_sent_rt_thread.start()
        ctrl_sent_pncc_thread.start()
        ctrl_sent_dcp_thread.start()
        ctrl_listen_thread.start()

        display_thread.join()
        ctrl_sent_rt_thread.join()
        ctrl_sent_pncc_thread.join()
        ctrl_sent_dcp_thread.join()
        ctrl_listen_thread.join()

    else:

        device_sent_alarm_thread= threading.Thread(target=device_send_alarm_messages)
        device_listen_thread = threading.Thread(target=device_packet_sniffer)

        display_thread.start()
        device_listen_thread.start()
        device_sent_alarm_thread.start()

        display_thread.join()
        device_listen_thread.join()
        device_sent_alarm_thread.join()
    