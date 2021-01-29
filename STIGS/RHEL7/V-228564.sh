#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-228564"
GrpTitle="SRG-OS-000057-GPOS-00027"
RuleID="SV-228564r606407_rule"
STIGID="RHEL-07-910055"
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

ls -al /var/log/audit >> $Results

if [ "$(find /var/log/audit -type f -perm /177 -o ! -user root -o ! -group root  2>>/dev/null )" ]; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
