#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the owner of the "cron.allow" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.

#STIG Identification
GrpID="V-72053"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86677r3_rule"
STIGID="RHEL-07-021110"
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

if [ -e /etc/cron.allow ]; then
 ls -l /etc/cron.allow >> $Results
 if [ "$(stat -Lc %U /etc/cron.allow)" == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "/etc/cron.allow does not exist" >> $Results 
 echo "Pass" >> $Results
fi
