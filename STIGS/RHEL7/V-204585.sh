#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204585"
GrpTitle="SRG-OS-000423-GPOS-00187"
RuleID="SV-204585r603261_rule"
STIGID="RHEL-07-040300"
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

if rpm -q openssh-server >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results 
fi
