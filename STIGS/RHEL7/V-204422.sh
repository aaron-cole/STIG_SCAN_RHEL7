#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

#STIG Identification
GrpID="V-204422"
GrpTitle="SRG-OS-000077-GPOS-00045"
RuleID="SV-204422r603261_rule"
STIGID="RHEL-07-010270"
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

scorecheck=0
chkfiles="/etc/pam.d/system-auth /etc/pam.d/password-auth"

for chkfile in $chkfiles; do
 if [ "$(awk '/^password.*pam_pwhistory.so.*remember=[5-9].*/' $chkfile)" ]; then
  echo "Pass - $chkfile - $(grep "^password.*pam_pwhistory.so.*remember=[5-9]" $chkfile)" >> $Results
 else
  echo "Fail - $chkfile - $(grep "^password.*pam__pwhistory.so.*remember=[5-9]" $chkfile)" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
