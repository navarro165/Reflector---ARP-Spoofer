# Reflector--ARP-Spoofer

### CSE 545: Software Security (ASU)

The goal of this project is to create a “reflector” which will relaunch attacks sent to a given IP address and ethernet address to the IP address that sent the attack. This acts as a mirror, such that when an adversary is ports canning a network, they will actually be port scanning themselves. When they launch an exploit at the reflector, the attack will be reflected back at them. To accomplish this task, you will improve your skills at network programming: creating raw packets, implementing ARP, and other low-level networking skills.

### Objectives
1. Develop a network program that sniffs all packets on a network interface
2. Apply the Address Resolution Protocol (ARP)
3. Implement ARP to impersonate a host on a local network
4. Create a program that can send raw network packets
