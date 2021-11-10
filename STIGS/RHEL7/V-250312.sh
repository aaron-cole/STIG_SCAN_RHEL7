#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-250312"
GrpTitle="SRG-OS-000324-GPOS-00125"
RuleID="SV-250312r792843_rule"
STIGID="RHEL-07-020021"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

#Check
scorecheck=0
semanage user -l >> $Results

users="guest_u root staff_u sysadmin_u system_u unconfined_u user_u xguest_u"

for user in $users; do
 tocheck="$(semanage user -l | grep ^$user | awk '{$1=$2=$3=$4="";print $0}' | sed 's/^     //g')"
 case $user in
    guest_u) checkvalue="guest_r" ;;
	root) checkvalue="staff_r sysadm_r system_r unconfined_r" ;;
	staff_u) checkvalue="staff_r sysadm_r" ;;
	sysadmin_u) checkvalue="sysadm_r" ;;
	system_u) checkvalue="system_r unconfined_r" ;;
	unconfined_u) checkvalue="system_r unconfined_r" ;;
	user_u) checkvalue="user_r" ;;
	xguest_u) checkvalue="xguest_r" ;; 
 esac  
 if [ "$checkvalue" != "$tocheck" ]; then
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
