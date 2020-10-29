#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-204483"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204483r505924_rule"
STIGID="RHEL-07-021021"
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

if mount | grep nfs | egrep -v "on /proc|sunrpc on" >> $Results; then 
 if [ "$(mount | grep nfs | grep noexec | wc -l)" == "$(mount | grep nfs | wc -l)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else 
 echo "No NFS mounts found" >> $Results
 echo "Pass" >> $Results
fi
