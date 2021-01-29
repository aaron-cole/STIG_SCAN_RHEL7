#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204632"
GrpTitle="SRG-OS-000375-GPOS-00160"
RuleID="SV-204632r603261_rule"
STIGID="RHEL-07-041002"
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

echo "sssd status- $(systemctl status sssd)" >> $Results

if [ "$(systemctl is-enabled sssd)" == "disabled" ] && [ "$(systemctl is-active sssd)" == "unknown" ]; then
 echo "Fail" >> $Results
else
 if [ "$(grep "^services =" /etc/sssd/sssd.conf | wc -l)" -eq 1 ]; then
  if grep "^services =.*pam" /etc/sssd/sssd.conf>> $Results; then
   echo "Pass" >> $Results
  else 
   echo "Fail" >> $Results
  fi
 else 
  echo "Multiple services lines found - Manual Check" >> $Results
  grep "^services =" /etc/sssd/sssd.conf>> $Results
  echo "Manual" >> $Results
 fi
fi
