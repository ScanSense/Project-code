#!/usr/bin/env python
import pandas as pd
import numpy as np
from ipaddress import IPv4Address
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import socket
from sklearn.ensemble import RandomForestClassifier
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
from tkinter import LEFT
from tkinter import RIGHT
from tkinter import Text
from tkinter import PhotoImage
from tkinter import Label, Message




# Define the mapping of ports to services
services = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    135: 'RPC Endpoint Mapper',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'Microsoft DS',
    465: 'SMTPS',
    587: 'SMTP (submission)',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'Microsoft SQL Server',
    1434: 'Microsoft SQL Monitor',
    3306: 'MySQL',
    3389: 'Remote Desktop Protocol',
    5432: 'PostgreSQL',
    5900: 'Virtual Network Computing (VNC)',
    8080: 'HTTP alternate'
}

# Load and preprocess the data
data = pd.read_csv('normalized_dataset.csv')
data['label'] = data['label'].astype(int)  # convert label column to integer
X = data.drop('label', axis=1)  # features
X.columns = range(X.shape[1])  # set feature names to integers
y = data['label']  # target variable

# Train the random forest classifier
rf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
rf.fit(X, y)

# Define function to trigger port scan and attack detection
scan_result = ""

def scan_ports():
    global scan_result
    # Get the IP address to scan from the user
    ip_address = ip_entry.get()

    # Port scan and attack detection
    open_ports = {}
    total_ports = len(services)
    progress = 0

    # Create progress bar widget with green color
    style = ttk.Style()
    style.configure("green.Horizontal.TProgressbar", background='green')
    progress_bar = ttk.Progressbar(main_tab, length=200, mode='determinate', style="green.Horizontal.TProgressbar")
    progress_bar.pack(pady=10)

    for port in services.keys():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            service_name = services[port]
            open_ports[port] = service_name
        sock.close()

        # Update progress bar
        progress += 1
        progress_percentage = (progress / total_ports) * 100
        progress_bar['value'] = progress_percentage
        main_tab.update_idletasks()

    # Destroy progress bar widget after scan completes
    progress_bar.destroy()

    if len(open_ports) == 0:
        scan_result = f"Target IP: {ip_address}\nOpen ports: None\nNo attack detected."
    else:
        scan_result = f"Target IP: {ip_address}\nOpen ports:\n"
        for port, service in open_ports.items():
            scan_result += f"- Port {port}: {service}\n"
        # Convert port scan results to feature vector
        port_vector = np.zeros(len(X.columns))
        for port in open_ports.keys():
            if port in X.columns:
                port_vector[X.columns.get_loc(port)] = 1

        # Predict using the trained random forest classifier
        result = rf.predict([port_vector])[0]
        if result == 0:
            scan_result += "No attack detected."
        else:
            if result == 1:
                scan_result += "Attack detected."
            messagebox.showwarning("Attack Detection Result", "Attack detected.")

    scan_result_label.configure(text=scan_result)

def scan_network(start_ip, end_ip):
    up_hosts = []
    for ip in range(int(IPv4Address(start_ip)), int(IPv4Address(end_ip)) + 1):
        target_ip = str(IPv4Address(ip))
        packet = IP(dst=target_ip) / ICMP()
        reply = sr1(packet, timeout=1, verbose=0)
        if reply and reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 0:
            up_hosts.append(target_ip)

    return up_hosts


# Create GUI window
root = tk.Tk()
root.title("SCAN SENSE")
root.geometry("800x800")
 

# Create a notebook widget
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Create the "Network Scan" tab frame
network_scan_tab = ttk.Frame(notebook)
# Add the "Network Scan" tab to the notebook
notebook.add(network_scan_tab, text="Network Scan")


# Add the main tab to the notebook
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Scan")

# Load the scan image
scan_image = Image.open("scan.png")
scan_image = scan_image.resize((150, 150), Image.LANCZOS)
scan_photo = ImageTk.PhotoImage(scan_image)


# Add the scan image to the main tab
scan_label = tk.Label(main_tab, image=scan_photo)
scan_label.pack(pady=10)

# Create a frame for the IP address label and entry field
ip_frame = tk.Frame(main_tab)
ip_frame.pack(side=tk.TOP, pady=20)


# Create label and entry field for IP address
ip_label = tk.Label(ip_frame, text="Enter the IP address to scan:")
ip_label.pack(side=tk.TOP, padx=10, pady=10)

ip_entry = tk.Entry(ip_frame)
ip_entry.pack(side=tk.TOP, padx=10, pady=10)

# Create label to display the port scan and attack detection results
scan_result_label = tk.Label(main_tab, text="")
scan_result_label.pack()

# Create the buttons and pack them side by side
scan_button = tk.Button(main_tab, text="Scan Ports", command=scan_ports)
scan_button.pack(side=tk.TOP, padx=(20, 5), pady=5)

def scan_network_button_click():
    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()
    up_hosts = scan_network(start_ip, end_ip)
    up_hosts_text = "\n".join(up_hosts)
    messagebox.showinfo("Up Hosts", f"Up Hosts:\n{up_hosts_text}")

# Add button to initiate network scan
scan_network_button = tk.Button(network_scan_tab, text="Scan Network", command=scan_network_button_click)
scan_network_button.pack(pady=10)

# Create a frame for the IP range label and entry fields
ip_range_frame = tk.Frame(network_scan_tab)
ip_range_frame.pack(side=tk.TOP, pady=10)

# Create label and entry fields for IP range
start_ip_label = tk.Label(ip_range_frame, text="Start IP:")
start_ip_label.pack(side=tk.LEFT, padx=5)

start_ip_entry = tk.Entry(ip_range_frame)
start_ip_entry.pack(side=tk.LEFT, padx=5)

end_ip_label = tk.Label(ip_range_frame, text="End IP:")
end_ip_label.pack(side=tk.LEFT, padx=5)

end_ip_entry = tk.Entry(ip_range_frame)
end_ip_entry.pack(side=tk.LEFT, padx=5)

# Create about_us_tab
about_us_tab = ttk.Frame(notebook)
notebook.add(about_us_tab, text="About ScanSense")

# Create a frame for the content and photo in the "About ScanSense" tab
about_content_frame = tk.Frame(about_us_tab)
about_content_frame.pack(pady=20)

# Add an image
about_image = Image.open("logo.png")
about_image = about_image.resize((150, 150), Image.LANCZOS)
about_photo = ImageTk.PhotoImage(about_image)
label = Label(about_content_frame, image=about_photo, text="""
Developed by: 
Ala’a Almajali
Aya Alshobaki 
Rahaf Albojoq
Sarah Alrashed 
Salsabeel Mousa
""", compound=tk.RIGHT, font=("Arial", 14), anchor='w')
label.image = about_photo
label.pack(pady=10)


# Create a big text box
text_box = Message(about_content_frame, width=780, text="""
Welcome to ScanSense!

ScanSense is a powerful Python-based port scanning and attack detection tool, 
designed to assist network administrators and security professionals
in detecting malicious activities within a network. It employs port scanning and attack detection, 
utilizing the Scapy library to identify open ports and determine associated services. 
ScanSense also utilizes a machine learning model for enhanced attack detection 
and offers network scanning functionality to identify active hosts with automation and real-time updates.
ScanSense ensures efficient and user-friendly scanning processes.""", pady=1) 

text_box.config(font=("Arial", 14))
# Center the text
text_box.pack()

# Load the photo for the about_us_tab
about_photo = Image.open("logo.png")
about_photo = about_photo.resize((900, 900), Image.LANCZOS)
about_photo_image = ImageTk.PhotoImage(about_photo)

root.mainloop()
