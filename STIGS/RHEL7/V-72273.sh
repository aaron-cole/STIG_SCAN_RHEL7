#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72273"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86897r2_rule"
STIGID="RHEL-07-040520"
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

if rpm -q firewalld >> $Results; then
 echo "Startup status- $(systemctl is-enabled firewalld)" >> $Results
 echo "Running status- $(systemctl is-active firewalld)" >> $Results
 if [ "$(systemctl is-enabled firewalld)" == "enabled" ] && [ "$(systemctl is-active firewalld)" == "active" ]; then
  echo "Current Firewalld State - $(systemctl status firewalld)" >> $Results
  if [ "$(firewall-cmd --state)" == "running" ]; then
   echo "Pass" >> $Results
  else 
   echo "Fail" >> $Results
  fi
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
