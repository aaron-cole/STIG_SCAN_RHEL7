#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-214801"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-214801r603261_rule"
STIGID="RHEL-07-032000"
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

if rpm -q ISecTP >> /dev/null; then
 rpm -q ISecTP >> $Results
 echo "Pass" >> $Results
elif rpm -q McAfeeTP >> /dev/null; then
 rpm -q McAfeeTP >> $Results
 echo "Pass" >> $Results
else
 echo "No AV Found - manual check" >> $Results
 echo "Fail" >> $Results
fi
