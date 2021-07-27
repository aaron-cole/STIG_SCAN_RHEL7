#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-228563"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-228563r744119_rule"
STIGID="RHEL-07-021031"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

#Check

wwdir="$(find / -perm -0002 -type d ! -user root ! -user bin ! -user sys 2>>/dev/null)"

if [ -n "$wwdir" ]; then
 echo "$wwdir" >> $Results
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
