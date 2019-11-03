#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a local interactive user’s files are group-owned by a group of which the user is not a member, unintended users may be able to access them.

#STIG Identification
GrpID="V-72025"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86649r2_rule"
STIGID="RHEL-07-020670"
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

for f in $(egrep "[0-9]{4}" /etc/passwd | egrep -v "nologin" | cut -f6 -d":"); do
 grpid="$(grep ":$f:" /etc/passwd | cut -f4 -d":")"
 if [ "$(find $f -not -group $grpid -print 2>>/dev/null )" ]; then
  ((scorecheck+=1))
  echo "$f - has files not owned by primary group" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
