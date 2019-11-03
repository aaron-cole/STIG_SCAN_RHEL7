#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72251"
GrpTitle="SRG-OS-000074-GPOS-00042"
RuleID="SV-86875r4_rule"
STIGID="RHEL-07-040390"
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

if [ "$(awk '/^Red Hat Enterprise Linux Server release/ {if($7 >= 7.4) {print}}' /etc/redhat-release)" ]; then
 echo "Server is RHEL 7.4 or greater - $(cat /etc/redhat-release)" >> $Results
 echo "NA" >> $Results
else 
 if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^Protocol" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
  awk -v opf="$Results" '/^Protocol/ {
	if($2 == 2) {
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
fi
