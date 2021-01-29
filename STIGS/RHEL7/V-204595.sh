#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204595"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-204595r603846_rule"
STIGID="RHEL-07-040400"
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

if [ "$(tail -n -1 ./Results/V-204497)" == "Fail" ]; then
 echo "V-204497 fails" >> $Results
 echo "Fail" >> $Results
elif [ -f /etc/ssh/sshd_config ] && [ "$(grep "^MACs" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
 awk -v opf="$Results" '/^MACs/ {
	if($2 == "hmac-sha2-512,hmac-sha2-256") {
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
