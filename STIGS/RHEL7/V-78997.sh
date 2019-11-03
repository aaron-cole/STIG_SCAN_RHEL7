#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-78997"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-93703r2_rule"
STIGID="RHEL-07-010101"
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
 if grep -r "/org/gnome/desktop/screensaver/idle-activation-enabled" /etc/dconf/db/local.d/locks >> $Results; then 
  echo "Pass" >> $Results
 else 
  echo "Gnome installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
