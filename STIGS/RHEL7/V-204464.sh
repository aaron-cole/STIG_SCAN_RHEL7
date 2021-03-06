#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.

#STIG Identification
GrpID="V-204464"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204464r603261_rule"
STIGID="RHEL-07-020330"
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
nogroups="$(find / -path /proc -prune -o -nogroup 2>>/dev/null | grep -v "^/proc")"

if [ -n "$nogroups" ]; then
 echo "Files Found - $nogroups" >> $Results 
 echo "Fail" >> $Results
else 
 echo "All files/dirs have valid group owners" >> $Results
 echo "Pass" >> $Results
fi
