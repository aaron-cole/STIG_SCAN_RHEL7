#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.

#STIG Identification
GrpID="V-72003"
GrpTitle="SRG-OS-000104-GPOS-00051"
RuleID="SV-86627r2_rule"
STIGID="RHEL-07-020300"
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

if pwck -r | grep "no group" >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
