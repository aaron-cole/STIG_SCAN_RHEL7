#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-73167"
GrpTitle="SRG-OS-000004-GPOS-00004"
RuleID="SV-87819r4_rule"
STIGID="RHEL-07-030872"
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

if ! auditctl -l | grep "\-w /etc/gshadow -p wa" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
