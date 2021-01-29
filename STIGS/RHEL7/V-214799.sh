#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-214799"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-214799r603261_rule"
STIGID="RHEL-07-010020"
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
TempDIR="./Results"

if grep "^..5" $TempDIR/RPMVA_status | grep -v " c " >> $Results; then 
 echo "Fail" >> $Results 
else 
 echo "Nothing Found, This is good" >> $Results 
 echo "Pass" >> $Results
fi
