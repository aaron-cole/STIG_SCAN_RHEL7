#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-81015"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-95727r1_rule"
STIGID="RHEL-07-030200"
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

if [ -f /etc/audisp/plugins.d/au-remote.conf ] && [ "$(grep "^active " /etc/audisp/plugins.d/au-remote.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^active / {
	if($3 == "yes") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audisp/plugins.d/au-remote.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi