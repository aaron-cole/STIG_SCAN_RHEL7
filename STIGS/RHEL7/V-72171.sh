#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72171"
GrpTitle="SRG-OS-000042-GPOS-00020"
RuleID="SV-86795r7_rule"
STIGID="RHEL-07-030740"
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

for f in b64 b32; do
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S.*[ ,]mount[, ].*-F auid>=1000 -F auid!=-1" >> $Results; then
  echo "$f mount rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done

for i in /usr/bin/mount; do
 if ! auditctl -l | grep "\-a always,exit -S all -F path=$i -F auid>=1000 -F auid!=-1" >> $Results; then
  echo "$f $i rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
