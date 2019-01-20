# Vector-IP-Scanner
An ip scanner for Anki's robot Vector to alleviate a changing ip address on a roaming DHCP server or needing to find the IP on new networks.

This program helps scanning for a Vector on a roaming DHCP server. When running for the first time, it will prompt for the ip address and serial if not found in `~/.anki_vector/sdk_config.ini`. Once a correct ip is given, the MAC address is saved. Every time the program is run, it will check the live ip/mac against the known Mac address. If the live mac address does not match Vector's, it will loop over all network interface subnets (255 per subnet) and will stop when Vector's mac address is found. If the IP has changed, it will use Anki's configure.py to set the new ip. 



# Installation

```
git clone https://github.com/GrinningHermit/Vector-IP-Scanner
cd Vector-IP-Scanner
pip3 install -r requirements.txt
python3 vector_ip_scanner.py

```

Tested on Linux and Mac, Windows should work but your mileage may vary.
