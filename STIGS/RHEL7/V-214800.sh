#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Adding endpoint security tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime.

#STIG Identification
GrpID="V-214800"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-214800r754751_rule"
STIGID="RHEL-07-020019"
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
if [ "$(rpm -qa | grep McAfeeTP)" ] && [ "$(ps -ef | grep -i "mfetpd" | grep -v grep)" ]; then
 rpm -qa | grep McAfeeTP >> $Results
 ps -ef | grep -i "mfetpd" >> $Results
 echo "Pass" >> $Results
else
 echo "McAfee ENSLTP not installed and/or running" >> $Results
 echo "Fail" >> $Results
fi
