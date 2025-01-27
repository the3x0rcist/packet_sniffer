# packet_sniffer

**Description:**

This is a packet sniffer for network engineers, using Scapy module, to monitor the network for ethernet packets.

This one uses python and if you didn't install python, Make sure you installed it already.

If you are using a Linux or Mac simply write this in your Terminal:

```sudo apt install python3```
```sudo apt instsall python3-scapy```

**Usage:**

Th usage is simply that you have to specify what interface you want to listen on with -i switch and you can also write the output into a file using -o switch.

```python3 sniffer.py -i eth0 -o captured.cap```

It starts listening for all the incoming packets and simply displays in your terminal window.

**Note:**

Please don't do anything malicious with this script.

GoodLuck :)

