#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The use of wireless networking can introduce many different attack vectors into the organization's network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.

#STIG Identification
GrpID="V-73177"
GrpTitle="SRG-OS-000424-GPOS-00188"
RuleID="SV-87829r2_rule"
STIGID="RHEL-07-041010"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

if  [ "$(dmidecode | grep "Product Name" | grep "VMware" | cut -f 2 -d":")" == " VMware Virtual Platform" ]; then
 echo "Wireless cards do not exist on Virtual Machines" >> $Results
 echo "NA" >> $Results
else
 if ip link | grep ": wl" >> $Results; then
  echo "Fail" >> $Results
 else
  echo "No Wireless interface found" >> $Results 
  echo "Pass" >> $Results
 fi
fi
