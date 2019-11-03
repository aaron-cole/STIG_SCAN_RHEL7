#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling DCCP protects the system against exploitation of any flaws in the protocol implementation.

#STIG Identification
GrpID="V-77821"
GrpTitle="SRG-OS-000378-GPOS-00163"
RuleID="SV-92517r3_rule"
STIGID="RHEL-07-020101"
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

grep -r "dccp" /etc/modprobe.d | grep -v "^#" >> $Results

if [ "$(grep -r "^install dccp \/bin\/true" /etc/modprobe.d)" ]; then 
 if [ "$(grep -r "^blacklist dccp" /etc/modprobe.d)" ]; then 
  echo "Pass" >> $Results 
 else
  echo "Blacklist Setting is not defined" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Install Setting is not defined" >> $Results 
 echo "Fail" >> $Results
fi
