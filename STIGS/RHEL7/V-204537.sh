#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204537"
GrpTitle="SRG-OS-000392-GPOS-00172"
RuleID="SV-204537r603261_rule"
STIGID="RHEL-07-030570"
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

if ! auditctl -l | grep "\-a always,exit -S all -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
