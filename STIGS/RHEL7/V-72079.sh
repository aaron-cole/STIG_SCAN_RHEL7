#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72079"
GrpTitle="SRG-OS-000038-GPOS-00016"
RuleID="SV-86703r3_rule"
STIGID="RHEL-07-030000"
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

echo "auditd status- $(systemctl status auditd)" >> $Results
echo "Running status- $(systemctl is-active auditd)" >> $Results

if [ "$(systemctl is-enabled auditd)" == "enabled" ] && [ "$(systemctl is-active auditd)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
