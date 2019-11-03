#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.

#STIG Identification
GrpID="V-72073"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86697r3_rule"
STIGID="RHEL-07-021620"
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

if ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Tripwire is installed" >> $Results
 echo "Pass" >> $Results 
elif rpm -q aide >> $Results; then
 if [ "$(tail -n -1 ./Results/V-72067)" == "Fail" ]; then
  echo "V-72067 fails" >> $Results
  echo "Fail" >> $Results
 else
  rules="$(grep "^/" /etc/aide.conf | grep -v "^#" | awk '{print $2}' | grep -v "^LOG" | sort | uniq)"
  aclrules="$(grep "sha512" /etc/aide.conf | grep -v "^#" | awk '{print $1}')"
  for rule in $rules; do
   if grep "^$rule" /etc/aide.conf | grep sha512 >> $Results; then 
     echo "" >> /dev/null
   else
    if [ "$(for aclrule in $aclrules; do if [ "$rule" == "$aclrule" ]; then echo "" >> /dev/null; else if grep "^$rule" /etc/aide.conf | grep $aclrule >> $Results; then echo "" >> /dev/null;fi;fi;done)" ]; then
     echo "" >> /dev/null
    else
     echo "$rule does not include sha512" >> $Results
	 ((scorecheck+=1))
    fi	
   fi
  done
 fi
else
 echo "Fail" >> $Results 
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
