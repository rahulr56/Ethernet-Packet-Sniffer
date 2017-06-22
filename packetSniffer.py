#!/usr/bin/ppython

import socket as s
import os
import struct 
import binascii

def analyseIPHeader(data):							# Refer IP RFC packet
	'''
	IP HEADER
		  0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	'''
	nextProto = ""
	ipHeader = struct.unpack("!6H4s4s",data[:20])		#  H-unsigned int refer struct help
	ver = ipHeader[0] >> 12							# Version is first 4 bits 
	ihl	= (ipHeader[0] >> 8) & 0x0f#00001111		# IHL is 4 bits after version
	tos = (ipHeader[0] & 0x00ff) 					# first byte is made 0 to remove version and IHL
	totalLength = ipHeader[1]
	ipIdentification = ipHeader[2]
	flags = ipHeader[3] >> 13						# flags is 3 bits
	fragOffset = ipHeader[3] & 0x1fff				# take off first 3 bits
	ipTTL = ipHeader[4] >> 8
	proto = ipHeader[4] & 0x00ff					# TCP /UDP
	chksum = ipHeader[5]
	srcAddr =  s.inet_ntoa(ipHeader[6])
	destAddr =  s.inet_ntoa(ipHeader[7])
	
	if proto == 6: #TCP Magic number
		nextProto = "TCP"
	if proto  == 17: 	# UDP
		nextProto = "UDP"
	print ("\n\n\n")
	print ("######################### IP HEADER #############################")
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|Version|  IHL  |Type of Service|          Total Length         |")
	print ("|  %s    |   %s   |        %s      |              %s              |"%(str(ver),str(ihl),str(tos),str(totalLength)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|         Identification        |Flags|      Fragment Offset    |")
	print ("|               %s           |  %s  |              %s          |"%(str(ipIdentification),str(flags),str(fragOffset)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|  Time to Live |    Protocol   |         Header Checksum       |")
	print ("|       %s      |       %s      |               %s          |"%(str(ipTTL),str(proto),str(chksum)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|                       Source Address           	        |")
	print ("|                       %s                             |"%str(srcAddr))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|                    Destination Address                        |")
	print ("|                       %s                         |"%str(destAddr))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")

	print (nextProto)
	return data , nextProto
	
	
def analyseTCPHeader(data):
	'''
	
  TCP Header Format


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	'''
	tcpHeader = struct.unpack("!2H2I4H" ,data[:20])
	srcPort = tcpHeader[0]
	dstPort = tcpHeader[1]
	seqNum  = tcpHeader[2]
	ackNum  = tcpHeader[3]
	dataOffset = tcpHeader[4] >> 12
	reserved = (tcpHeader[4] >> 6) & 0x03ff		# MUST be ZERO 
	flags = tcpHeader[4] & 0x003f
	urg = flags & 0x0020	# implies that Urgent pointer field is significant
	ack = flags & 0x0010	# 
	psh = flags & 0x0008	# have data for exchange
	rst = flags & 0x0004	# reset the connection
	syn = flags & 0x0002	# initial handshake
	fin = flags & 0x0001	# terminate a connection
	window = tcpHeader[5]	# amount of data to be sent
	checksum = tcpHeader[6]
	urgentPtr = tcpHeader[7]	# not mostly used. If used, the conn is malicious
	print ("\n\n\n")
	print ("__________________________ TCP HEADER ___________________________")
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|      Src Port : %s            |       Dest Port : %s          |"%(str(srcPort),str(dstPort)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|                        Sequence Number : %s                   |"%str(seqNum))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|                    Acknowledgment Number : %s                 |"%str(ackNum))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|  Data |           |U|A|P|R|S|F|                               |")
	print ("| Offset| Reserved  |R|C|S|S|Y|I|            Window : %s        |" %str(window))
	print ("|   %s  |    %s     |G|K|H|T|N|N|                               |"%(str(dataOffset),str(reserved)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
	print ("|           Checksum : %s     |         Urgent Pointer : %s     |"%(str(checksum),str(urgentPtr)))
	print ("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")

	return data[20:]
	
def analyseUDPHeader(data):	
	'''
	    0      7 8     15 16    23 24    31  
                 +--------+--------+--------+--------+ 
                 |     Source      |   Destination   | 
                 |      Port       |      Port       | 
                 +--------+--------+--------+--------+ 
                 |                 |                 | 
                 |     Length      |    Checksum     | 
                 +--------+--------+--------+--------+ 
                 |                                     
                 |          data octets ...            
                 +---------------- ...                 

                      User Datagram Header Format

	'''
	udpHeader = struct.unpack("!4H",data[:8])
	srcPort = udpHeader[0]
	dstPort = udpHeader[1]
	length  = udpHeader[2]
	chksum  = udpHeader[3]
	print ("\n\n\n")
	print (" ############# UDP HEADER ############")
	print (" +--------+--------+--------+--------+")
	print (" |     Src Port    |     Dest Port   | ")
	print (" |      %s         |        %s       | "%(str(srcPort),str(dstPort)))
	print (" +--------+--------+--------+--------+ ")
	print (" |     Length      |    Checksum     | ")
	print (" |      %s         |        %s       | "%(str(length),str(chksum)))
	print (" +--------+--------+--------+--------+ ")
	return data[8:]
	
def analyseEtherHeader(data):
	ipBool = False
	ethHeader = struct.unpack("!6s6sH" , data[:14])
	destMAC = binascii.hexlify(ethHeader[0])  # Destination address
	srcMAC = binascii.hexlify(ethHeader[1])	# Source Address
	proto = ethHeader[2]	# Next protocol
	print ("\n\n|------------------ ETHERNET HEADER ---------------|")
	print ("| Destination MAC\t:\t%s:%s:%s:%s:%s:%s  |"%(destMAC[0:2],destMAC[2:4],destMAC[4:6],destMAC[6:8],destMAC[8:10],destMAC[10:12]))
	print ("| Source MAC\t\t:\t%s:%s:%s:%s:%s:%s  |"%(srcMAC[0:2],srcMAC[2:4],srcMAC[4:6],srcMAC[6:8],srcMAC[8:10],srcMAC[10:12]))
	print ("| Protocol\t\t:\t%s\t\t   |"%hex(proto))
	print ("|--------------------------------------------------|")
	if proto == 0x800: #IPv4
		ipBool = True
		
	return data[14:],ipBool		# data after stripping header

def main():
	snifferSocket = s.socket(s.PF_PACKET, s.SOCK_RAW , s.htons(0x0003))
	#snifferSocket.bind() # RAW SCOKETS dont do this!
	receivedData = snifferSocket.recv(2048) # accept data of about 2KB
	
	data, ipBool = analyseEtherHeader (receivedData)
	nextProto = ""
	if ipBool:
		data , nextProto = analyseIPHeader(data)
		
		if nextProto == "TCP":
			data = analyseTCPHeader(data)
		if nextProto == "UDP":
			data = analyseUDPHeader(data)
		else:
			print ("Neither TCP nor UDP")
			return
	else:
		print ("Unknown Protocol")
while True:
	main()
