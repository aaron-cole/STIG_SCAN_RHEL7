#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

#STIG Identification
GrpID="V-72031"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86655r4_rule"
STIGID="RHEL-07-020700"
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

initfiles=".login .bash_profile .bashrc .cshrc .profile .tcshrc .kshrc"
for f in $(egrep "[0-9]{4}" /etc/passwd | egrep -v "nologin" | cut -f6 -d":"); do
 grpid="$(grep ":$f:" /etc/passwd | cut -f4 -d":")"
 for item in $initfiles; do 
  if [ -e $f/$item ]; then
   if [ "$(stat -c %g $f/$item 2>>/dev/null)" -eq "$grpid" ] || [ "$(stat -c %g $f/$item)" == "grpid" ]; then
	echo "" >> /dev/null
   else 
    ((scorecheck+=1))
    echo "$f/$item - Fix" >> $Results
   fi
  fi
 done
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
