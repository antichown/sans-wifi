import  sys, scapy
from datetime import datetime
from scapy.all import *
from sets import Set
THRESH = (254/4)
THRESH1 =(25/5)
START = 5
global reqCnt
global rtsCNT
global ctsCNT
global ofrCnt
reqCnt = 0
ofrCnt = 0
global ssidDict
global ssidCnt
global deauthCNT

def monitorPackets(p):
    global ssidDict
    global ssidCnt
    global hwTable
    global conCnt
    global rtsCNT
    global ctsCNT    
    hwTable = {}
    global deauthCNT
    
    if p.haslayer(Dot11):
        type = p.getlayer(Dot11).type
        subtype = p.getlayer(Dot11).subtype
        if ((type==0) and (subtype==12)):
            deauthCNT = deauthCNT + 1
            delta = datetime.now()-start
            if ((delta.seconds > START) and ((deauthCNT/delta.seconds) > THRESH1)):
                print "[*] - Detected Death Attack: "+str(deauthCNT)+" Dauth Frames."
                

    if p.haslayer(IP):
        hwSrc = p.getlayer(Ether).src
        if hwSrc not in hwList:
            hwList.append(hwSrc)
        delta = datetime.now() - start
        if ((delta.seconds > START) and ((len(hwList)/delta.seconds) > THRESH)):
            print "[*] - Detected CAM Table Attack."
        
        
    if p.haslayer(BOOTP):
        global reqCnt
        global ofrCnt
        opCode = p.getlayer(BOOTP).op
        if opCode == 1:
            reqCnt=reqCnt+1
        elif opCode == 2:
            ofrCnt=ofrCnt+1
        print "[*] - "+str(reqCnt)+" Requests, "+str(ofrCnt)+" Offers."
    
       
    if p.haslayer(Dot11):
        delta=datetime.now()-start
        if (p.getlayer(Dot11).subtype) == 11:
            rtsCNT = rtsCNT +1
            if ((delta.seconds > START) and ((rtsCNT/delta.seconds) > THRESH1)):
                print "[*] - Detected RTS Flood."
        elif (p.getlayer(Dot11).subtype) == 12:
            ctsCNT = ctsCNT + 1
            if ((delta.seconds > START) and ((ctsCNT/delta.seconds) > THRESH1)):
                print "[*] - Detected CTS Flood." 

    if p.haslayer(Dot11):
        if (p.getlayer(Dot11).subtype==8):
            ssid = p.getlayer(Dot11).info
            bssid = p.getlayer(Dot11).addr2
            stamp = str(p.getlayer(Dot11).timestamp)
            if bssid not in ssidDict:
                ssidDict[bssid] = []
                ssidCnt[bssid]=0
            elif (long(stamp) < long(ssidDict[bssid][len(ssidDict[bssid])-1])):
                ssidCnt[bssid]=ssidCnt[bssid]+1
                if (ssidCnt[bssid] > THRESH):
                    print "[*] - Detected fakeAP for: "+ssid
            ssidDict[bssid].append(stamp)
interface=sys.argv[1]
ssidDict = {}
ssidCnt = {}
hwList = []
ctsCNT = 0
rtsCNT = 0
deauthCNT = 0
start = datetime.now()

sniff(iface=interface,prn=monitorPackets)