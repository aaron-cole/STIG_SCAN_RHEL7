#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a local interactive user does not own their home directory, unauthorized users could access or modify the user's files, and the users may not be able to access their own files.

#STIG Identification
GrpID="V-72019"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86643r5_rule"
STIGID="RHEL-07-020640"
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
 user="$(grep ":$f:" /etc/passwd | cut -f1 -d":")"
 if [ "$(stat -c %U $f)" != "$user" ]; then 
  echo "$f - Fix" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
