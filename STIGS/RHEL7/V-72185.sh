#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

#STIG Identification
GrpID="V-72185"
GrpTitle="SRG-OS-000471-GPOS-00215"
RuleID="SV-86809r4_rule"
STIGID="RHEL-07-030810"
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

if ! auditctl -l | grep "\-a always,exit -S all -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
