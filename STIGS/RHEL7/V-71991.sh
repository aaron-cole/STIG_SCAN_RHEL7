#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71991"
GrpTitle="SRG-OS-000445-GPOS-00199"
RuleID="SV-86615r5_rule"
STIGID="RHEL-07-020220"
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

if [ -e /opt/isec/ens/threatprevention/bin/isecav ]; then
 echo "McAfee Endpoint Security for Linux Threat Prevention is installed and is a HIPS" >> $Results
 /opt/isec/ens/threatprevention/bin/isecav --version >> $Results
 echo "NA" >> $Results
else
 sestatus >> $Results
 if [ "$(sestatus | awk '/^Current mode/ {if($3 == "enforcing") {print}}')" ] && [ "$(sestatus | awk '/^Loaded policy name/ {if($4 == "targeted") {print}}')" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results 
 fi
fi
