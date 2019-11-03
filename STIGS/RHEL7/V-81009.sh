#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-81009"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-95721r2_rule"
STIGID="RHEL-07-021022"
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

if grep "/dev/shm" /etc/fstab | grep -v "^#" | grep nodev >> $Results; then
 if mount | grep "on /dev/shm " | grep nodev >> $Results; then
  echo "Pass" >> $Results
 else
  echo "/dev/shm is not mounted with the nodev option" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/dev/shm is NOT present with the nodev option in /etc/fstab" >> $Results
 echo "Fail" >> $Results
fi