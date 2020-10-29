#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.

#STIG Identification
GrpID="V-204479"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204479r505924_rule"
STIGID="RHEL-07-020900"
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

devicet="$(find / -context *:device_t:* \( -type c -o -type b \) 2>>/dev/null | egrep -v "/dev/vsock|/dev/vmci")"
unlabeledt="$(find / -context *:unlabeled_t:* \( -type c -o -type b \) 2>>/dev/null )"

if [ -n "$devicet" ] || [ -n "$unlabeledt" ]; then
 echo "files found associated with device_t $devicet" >> $Results
 echo "files found associated with unlabeled_t $unlabeledt" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
