#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204577"
GrpTitle="SRG-OS-000096-GPOS-00050"
RuleID="SV-204577r505924_rule"
STIGID="RHEL-07-040100"
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

echo "Ensure the PPSM CLSA is aligned with Firewall" >> $Results

if [ "$(systemctl is-enabled firewalld)" == "disabled" ] && [ "$(systemctl is-active firewalld)" == "unknown" ]; then
 echo "FirewallD is not running" >> $Results
else
 firewall-cmd --list-all >> $Results
 echo "Pass" >> $Results
fi

sed -i 's/^.*\[91mFirewallD is not running.*\[00m/FirewallD is not Running/' $Results
