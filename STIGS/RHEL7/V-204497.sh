#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204497"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-204497r603261_rule"
STIGID="RHEL-07-021350"
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

if rpm -q dracut-fips >> $Results; then
 echo "FIPS Startup - $(grep "fips=1" /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg 2>>/dev/null)" >> $Results
 echo "FIPS Running - $(cat /proc/sys/crypto/fips_enabled)" >> $Results
 if [ "$(grep "fips=1" /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg 2>>/dev/null)" ] && [ "$(cat /proc/sys/crypto/fips_enabled)" -eq "1" ]; then
  if [ -f /etc/system-fips ]; then
   echo "File Exists - $(ls -l /etc/system-fips 2>> /dev/null)" >> $Results
   echo "Pass" >> $Results
  else
   echo "File Doesn't Exist" >> $Results
   echo "Fail" >> $Results
  fi
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
