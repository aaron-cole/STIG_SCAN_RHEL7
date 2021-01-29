#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

#STIG Identification
GrpID="V-204620"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204620r603261_rule"
STIGID="RHEL-07-040690"
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

if rpm -q vsftpd >> $Results; then
 echo "Fail" >> $Results
elif netstat -antlp | grep ":2[01] " >> $Results; then
 echo "Another ftp package is installed other than vsftpd" >> $Results
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
