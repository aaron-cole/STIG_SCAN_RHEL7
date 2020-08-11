#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
# 

#STIG Identification
GrpID="V-72129"
GrpTitle="SRG-OS-000064-GPOS-00033"
RuleID="SV-86753r6_rule"
STIGID="RHEL-07-030530"
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

if [ "$(uname -i)" == "x86_64" ]; then
 rules="b64 b32"
else
 rules="b32"
fi

for f in $rules; do
 for i in EACCES EPERM; do
  if ! auditctl -l | grep "\-a always,exit -F arch=$f -S.*[ ,]open_by_handle_at[, ].*-F exit=-$i -F auid>=1000 -F auid!=-1" >> $Results; then
   echo "$f $i rule does not exist" >> $Results
   ((scorecheck+=1))
  fi
 done
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
