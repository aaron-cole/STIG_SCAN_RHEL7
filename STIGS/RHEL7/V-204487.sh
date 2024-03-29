#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204487"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204487r744106_rule"
STIGID="RHEL-07-021030"
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

wwdir="$(find / -perm -0002 -type d ! -group root ! -group bin ! -group sys 2>>/dev/null)"

if [ -n "$wwdir" ]; then
 echo "$wwdir" >> $Results
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
