#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

#STIG Identification
GrpID="V-72089"
GrpTitle="SRG-OS-000343-GPOS-00134"
RuleID="SV-86713r4_rule"
STIGID="RHEL-07-030330"
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

grep -i "^space_left =" /etc/audit/auditd.conf >> $Results

if rpm -q bc >> /dev/null; then
 KBtotalsize=$(df /var/log/audit | awk '{print $2}' | grep -v "block")
 MBtotalsize=$(((KBtotalsize+512)/1024))
 factor=".25"

 MBspace=$(echo $MBtotalsize*$factor | bc | cut -f 1 -d ".")
 echo "Total Space - $(df -h /var/log/audit)" >> $Results
 if grep -i "^space_left = $MBspace" /etc/audit/auditd.conf >> $Results; then
  echo "Pass" >> $Results
 else
  echo "Not Configured to 25% left of the partition" >> $Results
  echo "Should be configured to $MBspace" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "bc is not installed, this check can not be completed" >> $Results
 echo "Fail" >> $Results
fi
