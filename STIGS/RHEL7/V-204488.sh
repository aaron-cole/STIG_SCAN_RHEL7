#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

#STIG Identification
GrpID="V-204488"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204488r505924_rule"
STIGID="RHEL-07-021040"
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
 for item in $initfiles; do 
  if [ -e "$f/$item" ]; then
   if grep -i umask $f/$item 2>>/dev/null | grep -v "^#" | grep -v "077" >> $Results; then
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
