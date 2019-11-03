#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72223"
GrpTitle="SRG-OS-000163-GPOS-00072"
RuleID="SV-86847r4_rule"
STIGID="RHEL-07-040160"
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

justneedone=0

if grep "TMOUT" /etc/profile.d/* | grep -v "^#"  >> /dev/null; then
 chkfiles="$(grep "TMOUT" /etc/profile.d/* | grep -v "^#" | cut -f 1 -d ":" | sort | uniq)"
 for chkfile in $chkfiles; do
  if grep "TMOUT=[0-600]" $chkfile >> $Results; then
   if grep "readonly TMOUT" $chkfile >> $Results; then
    if grep "export TMOUT" $chkfile >> $Results; then
	 justneedone=1
	 break
    fi
   fi
  fi
 done
 if [ "$justneedone" -eq 1 ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else
 echo "No TMOUT found in any script located in /etc/profile.d/" >> $Results
 echo "Fail" >> $Results
fi 
