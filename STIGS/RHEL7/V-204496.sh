#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

#STIG Identification
GrpID="V-204496"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204496r505924_rule"
STIGID="RHEL-07-021340"
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

if findmnt /tmp >> $Results; then
 echo "Pass" >> $Results
elif [ "$(systemctl is-enabled tmp.mount)" == "enabled" ]; then
 echo "Pass" >> $Results
else
 echo "/tmp not on seperate partition" >> $Results  
 echo "Fail" >> $Results
fi
