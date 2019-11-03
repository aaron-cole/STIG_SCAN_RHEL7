#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72269"
GrpTitle="SRG-OS-000355-GPOS-00143"
RuleID="SV-86893r4_rule"
STIGID="RHEL-07-040500"
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

echo "NTP Status - $(systemctl status ntpd 2>> $Results)" >> $Results

if [ "$(systemctl is-enabled ntpd)" == "enabled" ] && [ "$(systemctl is-active ntpd)" == "active" ]; then
 grep maxpoll /etc/ntp.conf | grep -v "#" >> $Results
 if [[ "$(grep "maxpoll 17" /etc/ntp.conf | grep -v "#" )" ]] || [[ ! "$(grep "maxpoll " /etc/ntp.conf | grep -v "#" )" ]]; then
  echo "Setting not set or not defined" >> $Results
  echo "Fail" >> $Results
 else
  echo "Pass" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
