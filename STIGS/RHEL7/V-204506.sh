#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204506"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-204506r505924_rule"
STIGID="RHEL-07-030201"
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

if grep "^direction = out" /etc/audisp/plugins.d/au-remote.conf >> $Results; then
 if grep "^path = /sbin/audisp-remote" /etc/audisp/plugins.d/au-remote.conf >> $Results; then
  if grep "^type = always" /etc/audisp/plugins.d/au-remote.conf >> $Results; then
   if grep "^active = yes" /etc/audisp/plugins.d/au-remote.conf >> $Results; then
    echo "Pass" >> $Results
   else
    echo "active not set properly in /etc/audisp/plugins.d/au-remote.conf" >> $Results
    echo "Fail" >> $Results
   fi
  else
   echo "type not set properly in /etc/audisp/plugins.d/au-remote.conf" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "path not set properly in /etc/audisp/plugins.d/au-remote.conf" >> $Results
  echo "Fail" >> $Results
 fi 
else
 echo "direction not set properly in /etc/audisp/plugins.d/au-remote.conf" >> $Results
 echo "Fail" >> $Results
fi
