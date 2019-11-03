#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Failure to restrict system access to authenticated users negatively impacts operating system security.

#STIG Identification
GrpID="V-71955"
GrpTitle="SRG-OS-000480-GPOS-00229"
RuleID="SV-86579r3_rule"
STIGID="RHEL-07-010450"
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
 if grep "^^TimedLoginEnable=false" /etc/gdm/custom.conf >> $Results; then 
  echo "Pass" >> $Results
 else 
  echo "Gnome installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
