#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204578"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-204578r505924_rule"
STIGID="RHEL-07-040110"
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

if [ "$(tail -n -1 ./Results/V-72067)" == "Fail" ]; then
 echo "V-72067 fails" >> $Results
 echo "Fail" >> $Results
elif grep Ciphers /etc/ssh/sshd_config | egrep -vi "#|arcfour|cbc|blowfish|cast|gcm|3des|chacha" | egrep "aes128|aes192|aes256" >> $Results ; then 
 echo "Pass" >> $Results
else
 grep Ciphers /etc/ssh/sshd_config >> $Results 
 echo "Fail" >> $Results
fi
