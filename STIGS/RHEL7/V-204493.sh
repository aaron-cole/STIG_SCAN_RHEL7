#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

#STIG Identification
GrpID="V-204493"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204493r603840_rule"
STIGID="RHEL-07-021310"
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

if mount | grep "on /home" >> $Results; then
 echo "Pass" >> $Results
else
 echo "/home not on seperate partition" >> $Results 
 echo "Fail" >> $Results
fi
