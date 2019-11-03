#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).

#STIG Identification
GrpID="V-72317"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86941r2_rule"
STIGID="RHEL-07-040820"
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

if rpm -q libreswan >> $Results; then
 if [ "$(grep -i "conn" /etc/ipsec.conf | grep -v "#")" ] || [ "$(grep -r conn /etc/ipsec.d/* | grep -v "#")" ]; then
  echo "Startup status- $(systemctl is-enabled ipsec)" >> $Results
  echo "Running status- $(systemctl is-active ipsec)" >> $Results
  if [ "$(systemctl is-enabled ipsec)" == "enabled" ] && [ "$(systemctl is-active ipsec)" == "active" ]; then
   echo "Tunnels setup and Ipsec is enabled" >> $Results
   echo "Pass" >> $Results
  else
   echo "Fail" >> $Results
  fi
 else
  echo "No Tunnels setup" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
