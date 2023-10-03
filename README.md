# Networking Application

This repository contains a networking application written in C, leveraging the Windows Socket API and pcap library to perform various networking tasks.

## Features

- ICMP Ping implementation
- TCP Port scanning
- HTTP GET request sender
- TCP Server and Client communication
- Base64 encoding and decoding
- File transfer over TCP
- ARP request sender
- Packet sniffing using pcap

## Dependencies

- Winsock2
- ws2tcpip
- iphlpapi
- pcap

## Building

Ensure you have the necessary libraries and headers available on your system. Build the project using a C compiler like GCC or MSVC on Windows.

```bash
gcc -o networking_app main.c -lws2_32 -liphlpapi -lwpcap
