#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.

#STIG Identification
GrpID="V-204437"
GrpTitle="SRG-OS-000080-GPOS-00048"
RuleID="SV-204437r505924_rule"
STIGID="RHEL-07-010481"
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

awk '/^ExecStart=.*\/usr\/sbin\/sulogin/' /usr/lib/systemd/system/rescue.service >> $Results

if [ "$(awk '/^ExecStart=.*\/usr\/sbin\/sulogin/' /usr/lib/systemd/system/rescue.service)" ]; then
 echo "Pass" >> $Results 
else
 echo "Fail" >> $Results
fi
