#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-81013"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-95725r2_rule"
STIGID="RHEL-07-021024"
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

if grep "/dev/shm" /etc/fstab | grep -v "^#" | grep noexec >> $Results; then
 if mount | grep "on /dev/shm " | grep noexec >> $Results; then
  echo "Pass" >> $Results
 else
  echo "/dev/shm is not mounted with the noexec option" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/dev/shm is NOT present with the noexec option in /etc/fstab" >> $Results
 echo "Fail" >> $Results
fi