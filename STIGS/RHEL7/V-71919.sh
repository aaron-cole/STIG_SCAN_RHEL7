#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

#STIG Identification
GrpID="V-71919"
GrpTitle="SRG-OS-000073-GPOS-00041"
RuleID="SV-86543r3_rule"
STIGID="RHEL-07-010200"
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
chkfiles="/etc/pam.d/system-auth /etc/pam.d/password-auth"

for chkfile in $chkfiles; do
 if [ "$(awk '/^password.*pam_unix.so.*sha512.*/' $chkfile)" ]; then
  echo "Pass - $chkfile - $(grep "^password.*pam_unix.so.*sha512.*" $chkfile)" >> $Results
 else
  echo "Fail - $chkfile - $(grep "^password.*pam_unix.so.*sha512.*" $chkfile)" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
