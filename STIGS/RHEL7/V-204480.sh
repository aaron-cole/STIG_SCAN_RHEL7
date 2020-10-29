#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-204480"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204480r505924_rule"
STIGID="RHEL-07-021000"
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

if grep " /home " /etc/fstab | grep nosuid >> $Results; then
 if mount | grep "on /home" | grep nosuid >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "/home has nosuid set in fstab, but no set currently" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/home does not have nosuid set in fstab" >> $Results
 echo "Fail" >> $Results
fi
