#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.

#STIG Identification
GrpID="V-72087"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-86711r3_rule"
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
else
 echo "disk_full_action not set properly in /etc/audisp/audisp-remote.conf" >> $Results
 echo "Fail" >> $Results
fi
