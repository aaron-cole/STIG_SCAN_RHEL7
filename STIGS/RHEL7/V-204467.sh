#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204467"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204467r603826_rule"
STIGID="RHEL-07-020620"
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

if pwck -r | grep "directory" | grep "does not exist" | egrep -v "avahi-autoipd|ftp|saslauth|pulse|gnome|memcached|hacluster" >> $Results 2>>/dev/null; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
