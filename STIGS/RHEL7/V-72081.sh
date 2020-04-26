#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72081"
GrpTitle="SRG-OS-000046-GPOS-00022"
RuleID="SV-86705r5_rule"
STIGID="RHEL-07-030010"
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

if auditctl -s | grep "^failure 2" >> $Results; then
 echo "Pass" >> $Results
elif auditctl -s | grep "^failure 1" >> $Results; then
 if grep "^.*@" /etc/rsyslog.conf | grep -v "#" >> $Results; then 
  echo "Pass" >> $Results
 elif ps -ef | grep "snmp" >> $Results; then
  echo "SNMP is monitoring partition" >> $Results
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else 
 echo "audit failure flag not set" >> $Results
 echo "Fail" >> $Results
fi
