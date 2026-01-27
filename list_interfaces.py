from scapy.all import get_if_list, show_interfaces

print("Listing all network interfaces...")
show_interfaces()

print("\n---------------------------------------------------")
print("Look for the interface that says 'Wi-Fi' or has your IP (10.56.xxx.xxx)")
