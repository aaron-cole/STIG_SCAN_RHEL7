#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72229"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-86853r4_rule"
STIGID="RHEL-07-040190"
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

echo "Running status of SSSD - $(systemctl status sssd)" >> $Results
echo "" >> $Results

if [ "$(systemctl is-active sssd)" == "active" ]; then
 chksetting="ldap_tls_reqcert = demand"
 chksetting2="ldap_tls_reqcert = hard"
 domains="$(awk '/\[sssd\]/,/^domains = / { if ($0 ~ /^domains = /) {print} }' /etc/sssd/sssd.conf | awk ' {print substr($0, index($0,$3)) }' | sed 's/,//g')"
 numofdomains="$(echo $domains | wc -w)"
 if [ "$(egrep "^$chksetting|^$chksetting2" /etc/sssd/sssd.conf | wc -l)" -eq "$numofdomains" ]; then
  echo "Active Domains - $domains" >> $Results
  egrep "^$chksetting|^$chksetting2" /etc/sssd/sssd.conf >> $Results
  echo "Pass" >> $Results
 else
  echo "Setting does not exist in all active domains" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "LDAP is not being Utilized" >> $Results
 echo "NA" >> $Results
fi
