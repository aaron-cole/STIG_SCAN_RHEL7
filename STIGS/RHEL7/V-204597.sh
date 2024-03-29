#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an unauthorized user obtains the private SSH host key file, the host could be impersonated.

#STIG Identification
GrpID="V-204597"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204597r792834_rule"
STIGID="RHEL-07-040420"
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

for f in /etc/ssh/ssh_host*_key; do
 stat -c %n-%a $f >> $Results
 if [ "$(stat -c %a $f)" -eq "600" ]; then
  echo "" >> /dev/null
 else 
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
