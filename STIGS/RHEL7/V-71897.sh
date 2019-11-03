#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71897"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-86521r3_rule"
STIGID="RHEL-07-010090"
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

if rpm -q screen >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
