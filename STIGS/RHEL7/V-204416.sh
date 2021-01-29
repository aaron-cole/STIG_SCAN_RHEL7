#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

#STIG Identification
GrpID="V-204416"
GrpTitle="SRG-OS-000073-GPOS-00041"
RuleID="SV-204416r603261_rule"
STIGID="RHEL-07-010210"
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

if [ -f /etc/login.defs ] && [ "$(grep "^ENCRYPT_METHOD" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^ENCRYPT_METHOD/ {
	if($2 == "SHA512") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/login.defs
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
