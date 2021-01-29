#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204509"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-204509r603261_rule"
STIGID="RHEL-07-030300"
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

if [ "$(grep -i "^remote_server =" /etc/audisp/audisp-remote.conf | wc -m)" -gt 24 ]; then
 grep -i "^remote_server =" /etc/audisp/audisp-remote.conf >> $Results
 echo "Pass" >> $Results 
elif [ -f /etc/audisp/plugins.d/syslog.conf ] && [ "$(grep "active = yes" /etc/audisp/plugins.d/syslog.conf)" ]; then
 grep -i "^remote_server =" /etc/audisp/audisp-remote.conf >> $Results
 grep "active = yes" /etc/audisp/plugins.d/syslog.conf >> $Results
 if grep "^.*@" /etc/rsyslog.conf | grep -v "^#" >> $Results; then
  echo "Logs are being sent through syslog" >> $Results
  echo "Pass" >> $Results
 else
  echo "Logs Are not being sent through syslog" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "No valid configurations found" >> $Results
 echo "Fail" >> $Results
fi
