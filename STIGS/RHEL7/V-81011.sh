#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-81011"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-95723r2_rule"
STIGID="RHEL-07-021023"
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

if grep "/dev/shm" /etc/fstab | grep -v "^#" | grep nosuid >> $Results; then
 if mount | grep "on /dev/shm " | grep nosuid >> $Results; then
  echo "Pass" >> $Results
 else
  echo "/dev/shm is not mounted with the nosuid option" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/dev/shm is NOT present with the nosuid option in /etc/fstab" >> $Results
 echo "Fail" >> $Results
fi