#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204453"
GrpTitle="SRG-OS-000445-GPOS-00199"
RuleID="SV-204453r603261_rule"
STIGID="RHEL-07-020210"
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

getenforce >> $Results
if [ "$(getenforce)" == "Enforcing" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
