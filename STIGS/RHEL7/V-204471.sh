#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.

#STIG Identification
GrpID="V-204471"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204471r603261_rule"
STIGID="RHEL-07-020660"
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
 if [ "$(find $f -not -user $user -exec ls -l '{}' \; 2>>/dev/null )" ]; then
  ((scorecheck+=1))
  echo "$f - has files not owned by user" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
