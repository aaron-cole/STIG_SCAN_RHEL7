#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72217"
GrpTitle="SRG-OS-000027-GPOS-00008"
RuleID="SV-86841r3_rule"
STIGID="RHEL-07-040000"
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

if [ -e /etc/security/limits.conf ] && [ "$(grep "^\*.*hard.*maxlogins" /etc/security/limits.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^\*.*hard.*maxlogins/ {
	if($4 <= 10) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/security/limits.conf
else
 echo "Setting not defined in /etc/security/limits.conf or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi
