#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204426"
GrpTitle="SRG-OS-000118-GPOS-00060"
RuleID="SV-204426r603261_rule"
STIGID="RHEL-07-010310"
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
if [ -f /etc/default/useradd ] && [ "$(grep "^INACTIVE" /etc/default/useradd | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^INACTIVE/ {
	if($2 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/default/useradd
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
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
