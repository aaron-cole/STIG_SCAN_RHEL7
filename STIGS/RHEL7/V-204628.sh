#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts.

#STIG Identification
GrpID="V-204628"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204628r505924_rule"
STIGID="RHEL-07-040810"
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

if [ "$(systemctl is-enabled firewalld)" == "disabled" ] && [ "$(systemctl is-active firewalld)" == "unknown" ]; then
 if [ -e /etc/hosts.allow ] && [ "$(grep -v "^#" /etc/hosts.allow | egrep "ALLOW|DENY" >> $Results)" ]; then
  echo "Pass" >> $Results
 elif [ -e /etc/hosts.deny ] && [ "$(grep -v "^#" /etc/hosts.deny | egrep "ALLOW|DENY" >> $Results)" ]; then
  echo "Pass" >> $Results
 else
  echo "Firewall Disabled and TCPWrappers Are NOT being used" >> $Results
  echo "Fail" >> $Results
 fi
elif [ "$(systemctl is-enabled firewalld)" == "enabled" ] && [ "$(systemctl is-active firewalld)" == "active" ]; then
 if firewall-cmd --list-all >> $Results; then
  echo "Pass" >> $Results
 else
  if [ -e /etc/hosts.allow ] && [ "$(grep -v "^#" /etc/hosts.allow | egrep "ALLOW|DENY" >> $Results)" ]; then
   echo "TCPWRAPPERS /etc/hosts.allow in use" >> $Results
   echo "Pass" >> $Results
  elif [ -e /etc/hosts.deny ] && [ "$(grep -v "^#" /etc/hosts.deny | egrep "ALLOW|DENY" >> $Results)" ]; then
   echo "TCPWRAPPERS /etc/hosts.deny in use" >> $Results
   echo "Pass" >> $Results
  else
   echo "Firewall Enabled and No source Rules defined" >> $Results
   echo "Fail" >> $Results
  fi
 fi
else
 echo "Fail" >> $Results
fi
