#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.

#STIG Identification
GrpID="V-72301"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86925r2_rule"
STIGID="RHEL-07-040700"
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

if rpm -q tftp-server >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
