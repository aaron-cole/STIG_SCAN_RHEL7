#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204446"
GrpTitle="SRG-OS-000363-GPOS-00150"
RuleID="SV-204446r505924_rule"
STIGID="RHEL-07-020040"
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

if ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Tripwire installed and Running" >> $Results
 echo "Pass" >> $Results
elif rpm -q aide >> $Results; then
 if grep -r "/usr/sbin/aide --check" /etc/cron.* /etc/crontab /var/spool/cron/root | grep "mail" | grep -v "^#" >> $Results; then
  echo "Pass" >> $Results
 else
  echo "AIDE or mail setting not defined in cron files" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "AIDE or Tripwire is not installed" >> $Results
 echo "Fail" >> $Results 
fi
