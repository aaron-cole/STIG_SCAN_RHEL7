#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).

#STIG Identification
GrpID="V-72075"
GrpTitle="SRG-OS-000364-GPOS-00151"
RuleID="SV-86699r2_rule"
STIGID="RHEL-07-021700"
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

grubpaths="$(find / -not \( -path /boot -prune \) -name "grub.cfg" 2>>/dev/null )"
grubfile=""

if [ -e /boot/grub2/grub.cfg ]; then
 grubfile="/boot/grub2/grub.cfg"
elif [ -e /boot/efi/EFI/redhat/grub.cfg ]; then
 grubfile="/boot/efi/EFI/redhat/grub.cfg"
else
 echo "Regular Grub file not found" >> $Results
 echo "Fail" >> $Results
fi

if [ -n $grubfile ]; then
 if [ -z $grubpaths ]; then
  echo "No Other grub.cfg found" >> $Results
  grep ^menuentry /boot/grub2/grub.cfg >> $Results
  grep "set root" /boot/grub2/grub.cfg >> $Results
  if [ "$(grep -c ^menuentry /boot/grub2/grub.cfg)" == "$(grep -c "set root" /boot/grub2/grub.cfg)" ]; then
   echo "Pass" >> $Results
  else
   echo "Fail" >> $Results
  fi
 else
  echo "Found $grubpaths" >> $Results
  echo "Fail" >> $Results
 fi
fi
