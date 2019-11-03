#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71979"
GrpTitle="SRG-OS-000366-GPOS-00153"
RuleID="SV-86603r2_rule"
STIGID="RHEL-07-020060"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##
##END of Automatic Items##

###Check###

if [ -f /etc/yum.conf ] && [ "$(grep "^localpkg_gpgcheck" /etc/yum.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^localpkg_gpgcheck/ {
	if($2 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/yum.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
