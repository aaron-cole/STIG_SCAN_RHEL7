#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

#STIG Identification
GrpID="V-204406"
GrpTitle="SRG-OS-000069-GPOS-00037"
RuleID="SV-204406r603261_rule"
STIGID="RHEL-07-010119"
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

if grep "^password.*[required|requisite].*pam_pwquality.so.*retry=[1-3]" /etc/pam.d/system-auth >> $Results; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
