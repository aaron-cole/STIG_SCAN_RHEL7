#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244557"
GrpTitle="SRG-OS-000080-GPOS-00048"
RuleID="SV-244557r792838_rule"
STIGID="RHEL-07-010483"
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

if [ -e /boot/efi/EFI/redhat/grub.cfg ]; then 
 echo "UEFI" >> $Results
 echo "NA" >> $Results
elif [ "$(rpm -qi redhat-release-server | grep "^Version" | awk '{print $3}' | cut -f 2 -d ".")" -lt 2 ]; then
 rpm -q redhat-release-server >> $Results
 echo "NA" >> $Results
elif [ -e /boot/grub2/user.cfg ] && [ "$(grep 'set superusers=' /boot/grub2/grub.cfg)" ]; then
 grep 'set superusers=' /boot/grub2/grub.cfg >> $Results
 if grep 'set superusers=' /boot/grub2/grub.cfg | egrep -v "root|unlock" >> /dev/null; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else
 echo "superusers is not set" >> $Results 
 echo "Fail" >> $Results
fi
