#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-237635"
GrpTitle="SRG-OS-000373-GPOS-00156"
RuleID="SV-237635r792836_rule"
STIGID="RHEL-07-010343"
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

if grep 'timestamp_timeout=0' /etc/sudoers /etc/sudoers.d/* | grep "Defaults" | grep -v "^#" >> $Results; then  
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
