#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.

#STIG Identification
GrpID="V-204515"
GrpTitle="SRG-OS-000343-GPOS-00134"
RuleID="SV-204515r603261_rule"
STIGID="RHEL-07-030350"
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

if [ -f /etc/audit/auditd.conf ] && [ "$(grep "^action_mail_acct" /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^action_mail_acct/ {
	if($3 == "root") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audit/auditd.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
