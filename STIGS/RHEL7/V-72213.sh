#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72213"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86837r3_rule"
STIGID="RHEL-07-032000"
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

if rpm -q ISecTP >> $Results; then
 echo "McAfee ENSL Status - $(systemctl state isectpd 2>> $Results)" >> $Results
 if [ "$(systemctl is-enabled isectpd 2>>/dev/null)" == "enabled" ] && [ "$(systemctl is-active isectpd 2>>/dev/null)" == "active" ]; then
  /opt/isec/ens/threatprevention/bin/isecav --version >> $Results
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "McAfee ENSL is not installed" >> $Results
 echo "Fail" >> $Results
fi
