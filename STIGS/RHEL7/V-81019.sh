#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-81019"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-95731r1_rule"
STIGID="RHEL-07-030210"
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

if grep "^overflow_action" /etc/audisp/audispd.conf | egrep -vi "suspend|ignore|exec|warn|stop" | egrep -i "syslog|single|halt" >> $Results; then
 echo "Pass" >> $Results
else
 echo "overflow_action not set" >> $Results
 echo "Fail" >> $Results
fi
