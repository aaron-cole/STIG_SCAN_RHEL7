#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204458"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204458r505924_rule"
STIGID="RHEL-07-020250"
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

if [ -e /etc/redhat-release ] && [ "$(wc -l < /etc/redhat-release)" -eq 1 ]; then 
awk -v opf="$Results" '/^Red Hat Enterprise Linux Server / {
	if($7 >= 7.6) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/redhat-release
else
 echo "Setting doesn't exist or File has been edited" >> $Results 
 echo "Fail" >> $Results
fi
