#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

#STIG Identification
GrpID="V-71997"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86621r5_rule"
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
	if($7 >= 7.5) {
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
