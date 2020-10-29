#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204429"
GrpTitle="SRG-OS-000373-GPOS-00156"
RuleID="SV-204429r505924_rule"
STIGID="RHEL-07-010340"
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

if egrep "^[^#]*NOPASSWD|^[^#]*!authenticate" /etc/sudoers >> $Results; then 
 echo "Fail" >> $Results
else 
 if egrep -r "^[^#]*NOPASSWD|^[^#]*\!authenticate" /etc/sudoers.d >> $Results; then 
  echo "Fail" >> $Results
 else 
  echo "Nothing Found in /etc/sudoers or /etc/sudoers.d/ files" >> $Results
  echo "Pass" >> $Results 
 fi 
fi
