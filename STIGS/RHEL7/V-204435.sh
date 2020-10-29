#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Failure to restrict system access to authenticated users negatively impacts operating system security.

#STIG Identification
GrpID="V-204435"
GrpTitle="SRG-OS-000480-GPOS-00229"
RuleID="SV-204435r505924_rule"
STIGID="RHEL-07-010470"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^HostbasedAuthentication/ {
	if($2 == "no") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
