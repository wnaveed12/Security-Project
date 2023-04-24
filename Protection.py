from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff
from threading import Thread
import tkinter as tk

def monitor_traffic():
    # Set up a Scapy sniffing function to capture wireless traffic
    sniff(prn=process_packet, filter="wlan type data")

def process_packet(packet):
    # Check if the packet is a handshake packet
    if packet.haslayer(EAPOL):
        # Check if the packet is a 4-way handshake packet
        if packet[EAPOL].type == 3:
            # Get the key information from the packet
            key_info = packet[EAPOL].key_info

            # Check if the key information indicates a KRACK attack
            if key_info & 0x1 == 0 and key_info & 0x2 == 0 and key_info & 0x4 == 0 and key_info & 0x40 == 0:
                # Display a message when KRACK attack is detected
                label.config(text="KRACK attack detected!")
                label.update()

                # Perform the protection code to mitigate the attack
                # ...

                # Display a message when protection code is implemented
                label.config(text="Protection code implemented!")
                label.update()

                # Add the bad packet details to the listbox
                listbox.insert(tk.END, f"Source: {packet.addr2}    Destination: {packet.addr1}    Type: {packet.type}")

def start_monitoring():
    # Start the traffic monitoring thread
    Thread(target=monitor_traffic).start()

# Set up the GUI
root = tk.Tk()
root.title("KRACK Protection")
root.geometry("400x300")

# Add a label to display status messages
label = tk.Label(root, text="Click the button to start monitoring for KRACK attacks.")
label.pack()

# Add a button to start monitoring
button = tk.Button(root, text="Start monitoring", command=start_monitoring)
button.pack()

# Add a listbox to display the details of bad packets
listbox = tk.Listbox(root)
listbox.pack()

# Start the GUI main loop
root.mainloop()
