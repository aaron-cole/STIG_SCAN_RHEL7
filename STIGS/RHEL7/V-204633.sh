#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204633"
GrpTitle="SRG-OS-000375-GPOS-00160"
RuleID="SV-204633r505924_rule"
STIGID="RHEL-07-041003"
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

grep "cert_policy = " /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "#" >> $Results

if [ "$(grep "cert_policy = " /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "#" | grep ocsp_on | wc -l)" -eq 3 ]; then
 echo "Pass" >> $Results
else
 echo "Setting not defined properly or completely" >> $Results 
 echo "Fail" >> $Results
fi
