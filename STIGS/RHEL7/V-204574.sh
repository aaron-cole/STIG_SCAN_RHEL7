#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.

#STIG Identification
GrpID="V-204574"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204574r505924_rule"
STIGID="RHEL-07-031000"
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

if grep "^.*@" /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
