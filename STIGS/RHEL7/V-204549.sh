#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204549"
GrpTitle="SRG-OS-000037-GPOS-00015"
RuleID="SV-204549r505924_rule"
STIGID="RHEL-07-030700"
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
scorecheck=0
for f in sudoers sudoers.d; do
 if ! auditctl -l | grep "\-w /etc/$f -p wa" >> $Results; then
  echo "$f Rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi

