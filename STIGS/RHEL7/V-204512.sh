#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204512"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-204512r505924_rule"
STIGID="RHEL-07-030321"
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

if [ -f /etc/audisp/audisp-remote.conf ] && [ "$(grep "^network_failure_action" /etc/audisp/audisp-remote.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^network_failure_action/ {
	if($3 == "syslog" || $3 == "single" || $3 == "halt") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audisp/audisp-remote.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
