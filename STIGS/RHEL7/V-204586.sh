#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204586"
GrpTitle="SRG-OS-000423-GPOS-00187"
RuleID="SV-204586r603261_rule"
STIGID="RHEL-07-040310"
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

echo "SSHD status- $(systemctl status sshd)" >> $Results

if [ "$(systemctl is-enabled sshd)" == "enabled" ] && [ "$(systemctl is-active sshd)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
