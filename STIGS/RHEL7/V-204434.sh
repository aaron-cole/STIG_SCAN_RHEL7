#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Failure to restrict system access to authenticated users negatively impacts operating system security.

#STIG Identification
GrpID="V-204434"
GrpTitle="SRG-OS-000480-GPOS-00229"
RuleID="SV-204434r603261_rule"
STIGID="RHEL-07-010460"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PermitUserEnvironment/ {
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
