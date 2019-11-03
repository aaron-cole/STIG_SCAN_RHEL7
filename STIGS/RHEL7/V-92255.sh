#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization

#STIG Identification
GrpID="V-92255"
GrpTitle="SRG-OS-000196"
RuleID="SV-102357r1_rule"
STIGID="RHEL-06-020019"
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
if [ "$(rpm -qa | grep MFEhiplsm)" ] && [ "$(ps -ef | grep -i "hipclient")" ]; then
 echo "Running Status - $(service hipclient status 2>> $Results)" >> $Results
 echo "Startup Status - $(chkconfig hipclient --list 2>> $Results)" >> $Results
 echo "Pass" >> $Results
else
 echo "Selinux Status - $(getenforce)" >> $Results
 echo "Fail" >> $Results
fi