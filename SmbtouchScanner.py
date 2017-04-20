#!/usr/bin/env python
#
# Smbtouch Scanner
# By: 3gstudent
# License: BSD 3-Clause
'''

Automatically scan the inner network.
Use Smbtouch.exe to detect whether the target is vulnerable.
Protocol: SMB
Scan port:445
Note:
   You can also use protocl NBT and port 139,just change the Smbtouch-1.1.1.xml

You can get Smbtouch.exe from this:
https://github.com/x0rz/EQGRP_Lost_in_Translation/blob/master/windows/touches/Smbtouch-1.1.1.exe

'''
import os
import fileinput
#Start IP,change it
BeginIP = '192.168.1.1'
#End IP,change it
EndIP = '192.168.1.10'
#Log file
fp = open('log.txt', 'w+')

OldIP = '      <value>127.0.0.1</value>'
TempIP = OldIP
IP1 =  BeginIP.split('.')[0]
IP2 =  BeginIP.split('.')[1]
IP3 =  BeginIP.split('.')[2]
IP4 = BeginIP.split('.')[-1]
EndIP_last = EndIP.split('.')[-1]

for i in range(int(IP4)-1,int(EndIP_last)):
     ip = str(IP1+'.'+IP2+'.'+IP3+'.'+IP4)
     int_IP4 = int(IP4)
     int_IP4 += 1
     IP4 = str(int_IP4)
     NewIP= '      <value>'+ip+'</value>'
     for line in fileinput.input('Smbtouch-1.1.1.xml',inplace=1):  
     	print line.rstrip().replace(TempIP,NewIP)
     TempIP = NewIP			     
     Output = os.popen(r"Smbtouch-1.1.1.exe").read()
     Output = Output[0:Output.find('<config',1)]
     fp.writelines(Output)
     Flag = Output.find('[-] Touch failed')
     if Flag == -1 :
	print '[+] Touch success:	' +ip
     else:  
	print '[-] Touch failed:	' +ip
else:
     fp.close( )     
     for line in fileinput.input('Smbtouch-1.1.1.xml',inplace=1):  
     	print line.rstrip().replace(NewIP,OldIP)




