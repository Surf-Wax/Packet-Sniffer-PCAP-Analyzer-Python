'''
PCAP Processor

Written exclusively for Python 3.4.x or above

Overview:

The script ingests a standard PCAP File and creates a passive
asset map based on the observed UNIQUE activity and stores the
resultng map as a serialzed python object.  In addition, an html
file is generated that depicts the observed asset map.

'''
# Python Standard Library Module Imports

import sys               # System specifics
import platform          # Platform specifics
import os                # Operating/Filesystem Module
import pickle            # Object serialization
import time              # Basic Time Module
import re                # regular expression library
from binascii import unhexlify

# 3rd Party Libraries

from prettytable import PrettyTable   # pip install prettytable

'''


Simple PCAP File 3rd Party Library 
to process pcap file contents

To install the Library
pip install pypcapfile 

'''

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network   import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp


# Script Constants

NAME    = "PYTHON PCAP PROCESSOR"
VERSION = "MARCH 2023"
AUTHOR  = "B. Thorpe"
DEBUG   = True

# Script Constants

DEBUG = True

# Script Local Functions


class ETH:
    '''LOOKUP ETH TYPE'''
    def __init__(self):
    
        self.ethTypes = {}
        
        self.ethTypes[2048]   = "IPv4"
        self.ethTypes[2054]   = "ARP"
        self.ethTypes[34525]  = "IPv6"
            
    def lookup(self, ethType):
        
        try:
            result = self.ethTypes[ethType]
        except:
            result = "not-supported"
            
        return result

# MAC Address Lookup Class
class MAC:
    ''' OUI TRANSLATION MAC TO MFG'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('oui.pickle', 'rb') as pickleFile:
            self.macDict = pickle.load(pickleFile)
            
    def lookup(self, macAddress):
        try:
            result = self.macDict[macAddress]
            cc  = result[0]
            oui = result[1]
            return cc+","+oui
        except:
            return "Unknown"
        
# Transport Lookup Class

class TRANSPORT:
    ''' PROTOCOL TO NAME LOOKUP'''
    def __init__(self):
        
        # Open the transport protocol Address OUI Dictionary
        with open('protocol.pickle', 'rb') as pickleFile:
            self.proDict = pickle.load(pickleFile)
    def lookup(self, protocol):
        try:
            result = self.proDict[protocol]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

#PORTS Lookup Class

class PORTS:
    ''' PORT NUMBER TO PORT NAME LOOKUP'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('ports.pickle', 'rb') as pickleFile:
            self.portDict = pickle.load(pickleFile)
            
    def lookup(self, port, portType):
        try:
            result = self.portDict[(port,portType)]
            return result
        except:
            return "EPH"

if __name__ == '__main__':

        print("PCAP PROCESSOR")
        
        # Create Lookup Objects
        macOBJ  = MAC()
        traOBJ  = TRANSPORT()
        portOBJ = PORTS()
        ethOBJ  = ETH()     
        
        ''' Attemp to open a PCAP '''
        while True:
            targetPCAP = input("Target PCAP File: ")
            filename = os.path.basename(targetPCAP)
            filename = os.path.splitext(filename)[0]
            if not os.path.isfile(targetPCAP):
                print("Invalid File: Please enter valid path\n")
                continue      
            try:
                pcapCapture = open(targetPCAP, 'rb')
                capture = savefile.load_savefile(pcapCapture, layers=0, verbose=False)
                print("PCAP Ready for Processing")
                break
            except:
                # Unable to ingest pcap       
                print("!! Unsupported PCAP File Format !! ")
                continue

        totPackets      = 0
        pktCnt          = 0

        ''' Create new dictionaries to capture info '''
        ipObservations = {}
        portObservations = {}

        # Now process each packet
        for pkt in capture.packets:
            pktCnt += 1

            ''' # used for limiting packets to test table output
            if pktCnt > 100:
                continue
            '''
            # extract the hour the packet was captured
            timeStruct  = time.gmtime(pkt.timestamp)
            capHour     = timeStruct.tm_hour - 1     
            
            # Get the raw ethernet frame
            ethFrame = ethernet.Ethernet(pkt.raw())
            
            '''
            Ethernet Header
            0                   1                   2                   3                   4              
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                      Destination Address                                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                         Source Address                                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           EtherType           |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
            |                                                                                               |
            +                                            Payload                                            +
            |                                                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
            '''
                
            ''' ---- Extract the source mac address ---- '''
            srcMAC          = "".join(map(chr, ethFrame.src))
            srcMACLookup    = srcMAC[0:8].upper()
            # remove the colon seperators
            # note the variable names starting with fld, we will use these later
            srcMACLookup  = re.sub(':','',srcMACLookup) 
            
            # Attempt to lookup the mfg in our lookup table 
            # Country Code and Organization
            srcMFG  = macOBJ.lookup(srcMACLookup)    
            
            ''' Extract the destination mac address ---'''
            dstMAC          = "".join(map(chr, ethFrame.dst))
            dstMACLookup    = dstMAC[0:8].upper()
            # remove the colon seperators
            # note the variable names starting with fld, we will use these later
            dstMACLookup  = re.sub(':','',dstMACLookup) 
            
            # Attempt to lookup the mfg in our lookup table 
            # Country Code and Organization
            dstMFG = macOBJ.lookup(dstMACLookup)     
        
            ''' Lookup the Frame Type '''
            frameType = ethOBJ.lookup(ethFrame.type)
            
            print("====== ETHERNET LAYER =====\n")
            print("TIMESTAMP:", timeStruct)
            print("SRC MAC:  ", srcMAC)
            print("DST MAC:  ", dstMAC)
            print("SRC MFG:  ", srcMFG)
            print("DST MFG:  ", dstMFG)
            print("FRAME TYP:", frameType)
            print("="*40,"\n")
            
            ''' Process any IPv4 Frames '''
            
            if frameType == "IPv4":
                '''
                ipV4 Header
                0                   1                   2                   3  
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |Version|  IHL  |Type of Service|          Total Length         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |         Identification        |Flags|     Fragment Offset     |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |  Time to Live |    Protocol   |        Header Checksum        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                         Source Address                        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                      Destination Address                      |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                    Options                    |    Padding    |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
                '''
                
                ''' Extract the payload '''
                ipPacket = ip.IP(unhexlify(ethFrame.payload))
                ttl = ipPacket.ttl
                    
                ''' Extract the source and destination ip addresses '''
                srcIP = "".join(map(chr,ipPacket.src))
                dstIP = "".join(map(chr,ipPacket.dst))
                
                ''' Extract the protocol in use '''
                protocol = str(ipPacket.p)
                
                ''' Lookup the transport protocol in use '''
                transport = traOBJ.lookup(protocol)[0]


                print("====== IPv4 Transport LAYER =====\n")
                print("TTL:   ",   ttl)
                print("SRC-IP:",   srcIP)
                print("DST-IP:",   dstIP)
                print("Protocol:", protocol)
                print("="*40,"\n")
                
                if transport == "TCP":
                    
                    '''
                    TCP HEADER
                    0                   1                   2                   3  
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |          Source Port          |        Destination Port       |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                        Sequence Number                        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                     Acknowledgment Number                     |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    | Offset|  Res. |     Flags     |             Window            |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |            Checksum           |         Urgent Pointer        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                    Options                    |    Padding    |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    '''
                    
                    ''' Extract Payload '''
                    tcpPacket = tcp.TCP(unhexlify(ipPacket.payload))

                    ''' Extract source and destination port'''
                    srcPort = tcpPacket.src_port
                    dstPort = tcpPacket.dst_port

                    '''Lookup source and destination port names'''
                    portType = "TCP"    # not sure if this is the best way/necessary
                    srcPortName = portOBJ.lookup(str(srcPort), portType)
                    dstPortName = portOBJ.lookup(str(dstPort), portType)

                     
                elif transport == "UDP":
                    '''
                     0                   1                   2                   3  
                     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |          Source Port          |        Destination Port       |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |             Length            |            Checksum           |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     '''
                    
                    udpPacket = udp.UDP(unhexlify(ipPacket.payload))  

                    srcPort = udpPacket.src_port
                    dstPort = udpPacket.dst_port                                    
                  
                    '''Lookup source and destination port names'''
                    portType = "UDP"    # not sure if this is the best way/necessary
                    srcPortName = portOBJ.lookup(str(srcPort), portType)
                    dstPortName = portOBJ.lookup(str(dstPort), portType)

                elif transport == "ICMP":
                    '''
                     0                   1                   2                   3  
                     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |      Type     |      Code     |            Checksum           |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |                             protocol = str(ipPacket.p)                                  |
                     +                          Message Body                         +
                     |                                                               |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     '''
                    ''' 
                    **** YOUR CODE HERE ****
                
                    '''            
                    srcPort = ''
                    srcPortName = ''
                    dstPort = ''
                    dstPortName = ''
                    

            elif frameType == "ARP":
                '''
                0                   1      
                0 1 2 3 4 5 6 7 8 9 0 1 2 3
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |  Dst-MAC  |  Src-MAC  |TYP|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                           |
                +       Request-Reply       +
                |                           |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |        PAD        |  CRC  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                '''
                
                ''' 
                **** YOUR CODE HERE ****
            
                '''
                protocol = "ARP"
                transport = "ARP"

                srcIP = ''
                dstIP = ''
                srcPort = ''
                srcPortName = ''
                dstPort = ''
                dstPortName = ''   

            else:
                continue
            
            # Add relevant info to dictionary entry corresponding to the pktCnt (Unique packet number)
            value = (srcIP, dstIP, str(transport), srcMAC, dstMAC, srcMFG, dstMFG, srcPort, srcPortName, dstPort, dstPortName, ttl)

            if value in ipObservations.values():      # If unique combo already exists in dictionary
                continue  
            else:                      
                ipObservations[pktCnt] = (srcIP, dstIP, str(transport), srcMAC, dstMAC, srcMFG, dstMFG, srcPort, srcPortName, dstPort, dstPortName, ttl)    # Add to dictionary with occurance 1
            
            # Search Source Port Options and add to Port Dictionary
            for key, value in ipObservations.items():
                if value[7] in portObservations: #if unique port already exists in dict
                    continue
                else:
                    portObservations[value[7]] = (value[0], value[8])

            # Search Destination Port Options and add to Port Dictionary
            for key, value in ipObservations.items():
                if value[9] in portObservations: #if unique port already exists in dict
                    continue
                else:
                    portObservations[value[9]] = (value[0], value[10])

        # Create IP OBSERVATIONS prettytable and display, write to output file
        ipObsTable = PrettyTable(["SRC-IP", "DST-IP", "PROTOCOL", "SRC-MAC", "DST-MAC", "SRC-MFG", "DST-MFG", "SRC-PORT", "SRC-PORT-NAME", "DST-PORT", "DST-PORT-NAME", "TTL"])
        for key, value in ipObservations.items():
            ipObsTable.add_row(value)

        #ipObsTable.sortby="PROTOCOL"

        print("\nIP Observations")
        print(ipObsTable)

        # Make Reports Directory
        if not os.path.exists("./Reports/"):
            os.makedirs("./Reports/")

        # Write table to text file
        outfilename = './Reports/thorpe_ip_Observations_' + filename + '_Report.txt'
        with open (outfilename, "w") as file:
            file.write(str(ipObsTable))

        # Create PORT OBSERVATIONS prettytable and display, write to ouput file
        portObsTable = PrettyTable(["IP", "PORT", "PORT-DESCRIPTION"])
        for port, (ip, port_description) in portObservations.items():
            portObsTable.add_row([ip, port, port_description])
        
        #portObsTable.sortby="PORT"
        print("\nPORT Observations")
        print(str(portObsTable))

        # Write table to text file
        outfilename = './Reports/thorpe_port_Observations_' + filename + '_Report.txt'
        with open (outfilename, "w") as file:
            file.write(str(portObsTable))

        
        print("\n\nScript End")
        
