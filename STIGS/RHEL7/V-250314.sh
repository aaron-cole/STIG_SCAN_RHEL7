#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-250314"
GrpTitle="SRG-OS-000324-GPOS-00125"
RuleID="SV-250314r792849_rule"
STIGID="RHEL-07-020023"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

#Check

if ! grep sysadm_r /etc/sudoers /etc/sudoers.d/* 2>>/dev/null >> $Results; then
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
