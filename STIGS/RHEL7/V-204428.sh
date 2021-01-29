#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204428"
GrpTitle="SRG-OS-000329-GPOS-00128"
RuleID="SV-204428r603261_rule"
STIGID="RHEL-07-010330"
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

for file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
 if grep "^auth.*req.*pam_faillock.so" $file | grep " deny=3 " | grep " fail_interval=900 " | grep " even_deny_root " >> $Results; then
  if grep "^auth.*default=die.*pam_faillock.so" $file | grep " deny=3 " | grep " fail_interval=900 " | grep " even_deny_root " >> $Results; then
   if grep "^account.*required.*pam_faillock.so" $file >> $Results; then
    echo "" >> /dev/null
   else
    echo "Failed - account required pam_faillock.so not defined in $file" >> $Results
    ((scorecheck+=1))
   fi
  else
   echo "Failed - auth [default=die] pam_faillock.so not defined correctly in $file" >> $Results
   ((scorecheck+=1))
  fi
 else
  echo "Failed - auth required or requesite pam_faillock.so not defined correctly in $file" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
