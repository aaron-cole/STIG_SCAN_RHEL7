#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204575"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204575r603261_rule"
STIGID="RHEL-07-031010"
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
chkmods="imtcp imudp imrelp"

for chkmod in $chkmods; do
 if grep -i "^\$ModLoad $chkmod" /etc/rsyslog.conf >> $Results; then
  echo "Documentation is needed for log aggregation" >> $Results
  ((scorecheck+=1)) 
  echo "Pass" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Not setup as a Log Aggregation Server" >> $Results 
 echo "Pass" >> $Results
fi
