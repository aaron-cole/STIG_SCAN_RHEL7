#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.

#STIG Identification
GrpID="V-72307"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86931r4_rule"
STIGID="RHEL-07-040730"
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

if rpm -q xorg-x11-server-common >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
