#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204451"
GrpTitle="SRG-OS-000114-GPOS-00059"
RuleID="SV-204451r505924_rule"
STIGID="RHEL-07-020110"
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

if rpm -q autofs >> $Results; then
 echo "autofs status- $(systemctl status autofs)"  >> $Results
 if [ "$(systemctl is-enabled autofs)" == "disabled" ] && [ "$(systemctl is-active autofs)" == "unknown" ]; then
  echo "Pass"  >> $Results
 elif [ "$(systemctl is-enabled autofs)" == "disabled" ] && [ "$(systemctl is-active autofs)" == "inactive" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail"  >> $Results
 fi
else
 echo "autofs is not installed" >> $Results
 echo "Pass" >> $Results
fi
