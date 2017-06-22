# Ethernet-Packet-Sniffer

## 1. Abstract ##
* This work aims at capturing all the ethrnet packets in a network using python Raw Sockets.
* The captured packets are parsed and their **[Ethernet](http://networksorcery.com/enp/protocol/ethernet.htm), [IP](https://tools.ietf.org/html/rfc791#section-3.1) ,[TCP](https://tools.ietf.org/html/rfc793#section-3.1) ,[UDP](https://www.ietf.org/rfc/rfc768.txt) Headers** are printed
* This packet sniffer can be exteded for other protocols as well.
***
## 2. Implementation ##
 * Step 1 : Capture packets in LAN network using python [Raw Sockets](https://docs.python.org/2/library/socket.html)
 * Step 2 : Parse Ethernet Header and identify the protocol used
 * Step 3 : If the prtocol is IP, parse IP header to identify the next protocol
 * Step 4 : The data is further parsed if the identified protocol is either TCP or UDP.
 
***
## 3. Setup Requirements ##
* **Language**: Python
* **Interpreter**: 2.x or 3.x

***
## 4. Run the Application ##
python packetSniffer.py
 
***
## 5. References ##
1. [Etheret Header](http://networksorcery.com/enp/protocol/ethernet.htm)
2. [IP Header](https://tools.ietf.org/html/rfc791#section-3.1) 
3. [TCP Header](https://tools.ietf.org/html/rfc793#section-3.1)
4. [UDP Header](https://www.ietf.org/rfc/rfc768.txt)
5. [Cybrary](https://www.cybrary.it/)

***
## 6. Acknowledgements ##
* [Rahul](https://github.com/rahulr56)
