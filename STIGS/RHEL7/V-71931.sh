#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

#STIG Identification
GrpID="V-71931"
GrpTitle="SRG-OS-000076-GPOS-00044"
RuleID="SV-86555r3_rule"
STIGID="RHEL-07-010260"
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
systemaccounts="patrol heimdall oracle hacluster bb"

for user in $(cut -f1 -d ":" /etc/shadow); do
 case $user in
	patrol|heimdall|oracle|hacluster) echo "$user - System Account - excluded" >> $Results;;
	*)	if [[ "$(grep "^$user:" /etc/shadow | cut -f 2 -d ":")" =~ ^\$6* ]] && [[ "$user" != "root" ]]; then 
		 if [[ "$(grep "^$user:" /etc/shadow | cut -f 5 -d ":")" -gt 60 ]]; then 
		  echo "$user - Fix" >> $Results
		  ((scorecheck+=1))
         fi
		fi;;
esac
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
