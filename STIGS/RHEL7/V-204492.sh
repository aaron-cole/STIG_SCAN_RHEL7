#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

#STIG Identification
GrpID="V-204492"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204492r505924_rule"
STIGID="RHEL-07-021300"
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

echo "kdump status- $(systemctl status kdump)" >> $Results

if [ "$(systemctl is-enabled kdump)" == "disabled" ] && [ "$(systemctl is-active kdump)" == "inactive" ]; then
 echo "Pass" >> $Results
elif [ "$(systemctl is-enabled kdump)" == "disabled" ] && [ "$(systemctl is-active kdump)" == "unknown" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
