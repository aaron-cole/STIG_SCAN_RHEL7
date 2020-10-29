#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204444"
GrpTitle="SRG-OS-000324-GPOS-00125"
RuleID="SV-204444r505924_rule"
STIGID="RHEL-07-020020"
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

disregardlist="$(cat /etc/passwd | cut -f 1,3 -d":" | egrep ":[0-9]{1,3}$" | cut -f 1 -d":" | tr \\n \|)"
disregardlist+="^__default__|^system_u"

if semanage login -l | egrep -v "$disregardlist" | grep "unconfined_u" >> $Results; then
 echo "Non-Mapped Users Found make sure none are service accounts" >> $Results
 echo "Fail" >> $Results
else
 semanage login -l >> $Results
 echo "Users are mapped correctly" >> $Results
 echo "Pass" >> $Results
fi
