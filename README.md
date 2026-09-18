# FULL ARP SPOOFER

> 🪐   ARP spoofer that poisons every host on the local `/24` network.

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ **Educational use only.** Use it only on networks you own or have
> explicit permission to test. Unauthorized use is illegal.

## Overview

ARP NetSpoofer is a small Python tool that performs ARP spoofing on a
local `/24` network. It scans the subnet, poisons the ARP tables of the
target devices and the gateway, and forwards traffic through your
machine to keep the connection alive.


## Features ⭐

- ARP scan of the local `/24` network
- Bidirectional spoofing (victim ↔ gateway)
- Automatic IP forwarding activation
- Automatic state restore on exit (`Ctrl+C`)
- Restores `ip_forward` and the `FORWARD` policy of iptables

## Requirements

- Linux
- Python 3.10+
- root privileges
- The following system tools: `iptables`, `ip`

## Installation

```bash
git clone https://github.com/WilliamsACE/arp-netspoofer.git
cd arp-netspoofer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt