#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

#STIG Identification
GrpID="V-204516"
GrpTitle="SRG-OS-000327-GPOS-00127"
RuleID="SV-204516r603261_rule"
STIGID="RHEL-07-030360"
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
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C uid!=euid -F euid=0" >> $Results; then
  echo "$f uid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C gid!=egid -F egid=0" >> $Results; then
  echo "$f gid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
