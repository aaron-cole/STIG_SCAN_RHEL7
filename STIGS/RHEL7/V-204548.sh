#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204548"
GrpTitle="SRG-OS-000037-GPOS-00015"
RuleID="SV-204548r603261_rule"
STIGID="RHEL-07-030690"
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

if ! auditctl -l | grep "\-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
