#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204442"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-204442r603261_rule"
STIGID="RHEL-07-020000"
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

if rpm -q rsh-server >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
