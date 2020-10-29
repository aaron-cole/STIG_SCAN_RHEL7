#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204618"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204618r505924_rule"
STIGID="RHEL-07-040670"
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

if ip link| grep promisc >> $Results; then
 echo "Fail" >> $Results
else 
 echo "No interfaces in promisc mode" >> $Results
 echo "Pass" >> $Results
fi
