#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

#STIG Identification
GrpID="V-204417"
GrpTitle="SRG-OS-000073-GPOS-00041"
RuleID="SV-204417r603261_rule"
STIGID="RHEL-07-010220"
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

if [ -f /etc/libuser.conf ] && [ "$(grep "^crypt_style" /etc/libuser.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^crypt_style/ {
	if($3 == "sha512") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/libuser.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
