#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204486"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-204486r505924_rule"
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

if grep "/dev/shm" /etc/fstab | grep -v "^#" | grep noexec | grep nosuid | grep nodev >> $Results; then
 if mount | grep "on /dev/shm " | grep noexec | grep nosuid | grep nodev >> $Results; then
  echo "Pass" >> $Results
 else
  echo "/dev/shm is not mounted with the required options" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/dev/shm is NOT present with the required options in /etc/fstab" >> $Results
 echo "Fail" >> $Results
fi
