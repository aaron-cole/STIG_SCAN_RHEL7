#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71947"
GrpTitle="SRG-OS-000373-GPOS-00156"
RuleID="SV-86571r3_rule"
STIGID="RHEL-07-010340"
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
function fail {
if egrep "^[^#]*NOPASSWD" /etc/sudoers >> $Results; then 
 echo "Fail" >> $Results
else 
 if egrep -r "^[^#]*NOPASSWD" /etc/sudoers.d >> $Results; then 
  echo "Fail" >> $Results
 else 
  echo "Nothing Found in /etc/sudoers.d/ files" >> $Results
  echo "Pass" >> $Results 
 fi 
fi
}

if [ "$(systemctl is-enabled sssd)" == "enabled" ] && [ "$(systemctl is-active sssd)" == "active" ]; then
 if [ "$(grep "^id_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "^auth_provider = ipa" /etc/sssd/sssd.conf)" ] && [ "$(grep "access_provider = ipa" /etc/sssd/sssd.conf)" ]; then
  if [ "$(awk '/^auth.*pam_sss.so/' /etc/pam.d/system-auth)" ] && [ "$(awk '/^account.*pam_sss.so/' /etc/pam.d/system-auth)" ]; then
   echo "IDM is in use which is CAC/ALT only authentication - No Passwords" >> $Results
   echo "NA" >> $Results
  else
   fail
  fi
 else
  fail
 fi
else
 fail
fi
