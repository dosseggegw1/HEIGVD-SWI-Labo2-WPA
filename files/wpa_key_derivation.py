#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)

Modified : Julien Béguin & Gwendoline Dössegger
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
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
        #BNonce = raw(trame)[67:99]
        #print(b"nous A : "+ANonce)
        #print(b"nous A : "+BNonce)
        #print(b"prof A : "+a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91"))
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
        #print(b"nous S : "+SNonce)
        #print(b"prof S : "+a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577"))


    # Get the WPA key MIC
    elif compteur2 > compteur and trame.subtype == 0x0 and trame.type == 0x0 and raw(trame)[18:24] == APmac and  raw(trame)[24:30] == Clientmac:
        mic_to_test = raw(trame)[-18:-2].hex()
        #print("nous mic : "+mic_to_test)
        #print("prof mic : 36eef66540fa801ceee2fea9b7929b40")

    compteur2 += 1

#---------------------------------------------------------------
# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

#ssid        = "SWI"
#APmac       = a2b_hex("cebcc8fdcab7")
#Clientmac   = a2b_hex("0013efd015bd")
# Authenticator and Supplicant Nonces
#ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
#SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# mic_to_test = "36eef66540fa801ceee2fea9b7929b40"


print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
