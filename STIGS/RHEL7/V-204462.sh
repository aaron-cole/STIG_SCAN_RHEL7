#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an account other than root also has a User Identifier (UID) of "0", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of "0" afford an opportunity for potential intruders to guess a password for a privileged account.

#STIG Identification
GrpID="V-204462"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204462r603261_rule"
STIGID="RHEL-07-020310"
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

if grep -v root /etc/passwd | cut -f3 -d: | grep "^0$" >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Root is only account with UID of 0" >> $Results
 echo "Pass" >> $Results
fi
