#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204441"
GrpTitle="SRG-OS-000104-GPOS-00051"
RuleID="SV-204441r792823_rule"
STIGID="RHEL-07-010500"
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

echo "authconfig settings:" >> $Results
authconfig --test | egrep -i "pam_pkcs11|smartcard removal action|smartcard module" >> $Results
 
if [ "$(authconfig --test | awk '/pam_pkcs11 is enabled/')" ]; then
 if [ "$(authconfig --test | awk '/ smartcard removal action = "Lock"/')" ]; then
  if [ "$(authconfig --test | awk '/ smartcard module = "coolkey"/')" ] || [ "$(authconfig --test | awk '/ smartcard module = "cackey"/')" ]; then
   echo "Pass" >> $Results
  else
   echo "Smartcard Module not set properly" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "Smartcard removal action not set properly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "pam_pkcs11 is not enabled" >> $Results
 echo "Fail" >> $Results
fi
