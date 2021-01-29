#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the group owner of the "cron.allow" file is not set to root, sensitive information could be viewed or edited by unauthorized users.

#STIG Identification
GrpID="V-204491"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204491r603261_rule"
STIGID="RHEL-07-021120"
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
 if [ "$(stat -Lc %G /etc/cron.allow)" == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "/etc/cron.allow does not exist" >> $Results 
 echo "Pass" >> $Results
fi

