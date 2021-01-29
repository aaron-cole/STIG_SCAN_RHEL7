#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204511"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-204511r603261_rule"
STIGID="RHEL-07-030320"
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

if grep "^disk_full_action" /etc/audisp/audisp-remote.conf | egrep -vi "suspend|ignore|exec|warn|stop" | egrep -i "syslog|single|halt" >> $Results; then
 echo "Pass" >> $Results
elif grep "^action = yes" /etc/audisp/plugins.d/syslog.conf >> $Results; then
 if grep "^.*@" /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
  echo "Logs are being to sent through rsyslog to remote log server" >> $Results
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "disk_full_action not set properly in /etc/audisp/audisp-remote.conf" >> $Results
 echo "Fail" >> $Results
fi
