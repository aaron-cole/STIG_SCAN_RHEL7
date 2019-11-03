#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71893"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-86517r5_rule"
STIGID="RHEL-07-010070"
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

if rpm -q gnome-desktop3 >> $Results; then 
 if grep -r "^idle-delay=uint32 900" /etc/dconf/db/local.d/* >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "Gnome installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
