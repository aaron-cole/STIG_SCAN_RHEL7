#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-219059"
GrpTitle="SRG-OS-000114-GPOS-00059"
RuleID="SV-219059r603261_rule"
STIGID="RHEL-07-020111"
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
scorecheck=0

if rpm -q gnome-desktop3 >> $Results; then 
 if [ "$(grep -r "automount=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l)" -eq 1 ]; then
  grep -r "automount=" /etc/dconf/db/local.d/* >> $Results
  if [ "$(grep -r "automount=" /etc/dconf/db/local.d/* | cut -f 2 -d "=")" == "false" ]; then
   echo "automount Setting defined and set" >> $Results
  else
   echo "automount Setting defined and NOT set" >> $Results
   ((scorecheck+=1))
  fi
 elif [ "$(grep -r "automount=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l )" -eq 0 ]; then
  echo "automount Setting not defined" >> $Results
 ((scorecheck+=1))
 else
  echo "More than 1 automount configuration" >> $Results
  ((scorecheck+=1))
 fi
 if [ "$(grep -r "automount-open=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l)" -eq 1 ]; then
  grep -r "automount-open=" /etc/dconf/db/local.d/* >> $Results
  if [ "$(grep -r "automount-open=" /etc/dconf/db/local.d/* | cut -f 2 -d "=")" == "false" ]; then
   echo "automount-open Setting defined and set" >> $Results
  else
   echo "automount-open Setting defined and NOT set" >> $Results
   ((scorecheck+=1))
  fi
 elif [ "$(grep -r "automount-open=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l )" -eq 0 ]; then
  echo "automount-open Setting not defined" >> $Results
 ((scorecheck+=1))
 else
  echo "More than 1 automount-open configuration" >> $Results
  ((scorecheck+=1))
 fi 
 if [ "$(grep -r "autorun-never=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l)" -eq 1 ]; then
  grep -r "autorun-never=" /etc/dconf/db/local.d/* >> $Results
  if [ "$(grep -r "autorun-never=" /etc/dconf/db/local.d/* | cut -f 2 -d "=")" == "true" ]; then
   echo "autorun-never Setting defined and set" >> $Results
  else
   echo "autorun-never Setting defined and NOT set" >> $Results
   ((scorecheck+=1))
  fi
 elif [ "$(grep -r "autorun-never=" /etc/dconf/db/local.d/* | grep -v "^#" | wc -l )" -eq 0 ]; then
  echo "autorun-never Setting not defined" >> $Results
 ((scorecheck+=1))
 else
  echo "More than 1 autorun-never configuration" >> $Results
  ((scorecheck+=1))
 fi
 if [ "$scorecheck" != 0 ]; then
  echo "Fail" >> $Results 
 else 
  echo "Pass" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi

