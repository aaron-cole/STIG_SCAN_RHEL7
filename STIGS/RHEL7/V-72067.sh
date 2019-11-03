#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-72067"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-86691r4_rule"
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
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
