#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.

#STIG Identification
GrpID="V-72261"
GrpTitle="SRG-OS-000364-GPOS-00151"
RuleID="SV-86885r3_rule"
STIGID="RHEL-07-040440"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^KerberosAuthentication" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^KerberosAuthentication/ {
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
