# Packet Monster

**Packet Monster** is a lightweight Windows packet sniffer built with the [WinDivert](https://reqrypt.org/windivert.html) library. It captures **inbound TCP/UDP packets**, extracts source and destination IP addresses and ports, and guesses the **application protocol** (like HTTP, DNS, SSH) based on well-known ports all in real time!


## 🎯 Features

- Protocol guessing based on known ports (HTTP, HTTPS, DNS, SSH, etc.)
- IPv4 and IPv6 support
- Handles TCP and UDP traffic
- Live terminal output with IP:Port info
- Reinjects packets without modification


