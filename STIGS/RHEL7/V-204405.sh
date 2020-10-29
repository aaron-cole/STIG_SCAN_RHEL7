#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important security function could be bypassed if stack entries are not centralized.

#STIG Identification
GrpID="V-204405"
GrpTitle="SRG-OS-000069-GPOS-00037"
RuleID="SV-204405r505924_rule"
STIGID="RHEL-07-010118"
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

if grep "^password.*substack.*system-auth" /etc/pam.d/passwd >> $Results; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
