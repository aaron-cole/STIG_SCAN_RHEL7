#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

#STIG Identification
GrpID="V-204588"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204588r505924_rule"
STIGID="RHEL-07-040330"
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
 if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^RhostsRSAAuthentication" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
  awk -v opf="$Results" '/^RhostsRSAAuthentication/ {
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
fi
