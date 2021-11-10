#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-250313"
GrpTitle="SRG-OS-000324-GPOS-00125"
RuleID="SV-250313r792846_rule"
STIGID="RHEL-07-020022"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

#Check

getsebool ssh_sysadm_login | awk '{$2=""; print $0}' >> $Results

if [ "$(getsebool ssh_sysadm_login | awk '{print $3}')" != "on" ]; then
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
