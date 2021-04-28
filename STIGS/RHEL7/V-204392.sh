#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-204392"
GrpTitle="SRG-OS-000257-GPOS-00098"
RuleID="SV-204392r646841_rule"
STIGID="RHEL-07-010010"
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
TempDIR="./Results"
#Output=""

if [ ! -e $TempDIR/RPMVA_status ]; then
 echo "Check not Performed" >> $Results
 exit
fi

for fn in $(grep "^.M" $TempDIR/RPMVA_status | sed 's/^.............//'); do 
 if [ "$(echo $fn | cut -c 1)" != "/" ]; then
  continue
 fi
 installedperms="$(rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:octal}\n]" $(rpm -qf $fn) | grep "^$fn " | sort | uniq | cut -f2 -d" ")"
 if [[ "$fn" =~ "/etc/ipa/nssdb/" ]] || [ "$fn" = "/var/log/dmesg" ] || [ "$fn" = "/var/log/dmesg.old" ]; then 
  echo "Red Hat Bugzilla 1571909" >> /dev/null
 elif [ "$fn" = "/etc/sysconfig/kernel" ] || [ "$fn" = "/etc/pki/ca-trust/source/ipa.p11-kit" ]; then 
  echo "Red Hat Bugzilla 1571909" >> /dev/null
 else
  actualperms="$(stat -c %a $fn)"
  start=1
  case ${#installedperms} in
      5) startcut=2
		 savedcut=2;;
	  6) startcut=3
		 savedcut=3;;
  esac
  if [ ${#actualperms} = 3 ]; then
   actualperms="0$actualperms"
  fi
  
  while [ "$start" -le 4 ] ; do
     installnum="$(echo $installedperms | cut -c $startcut)"
     actualnum="$(echo $actualperms | cut -c $start)"
 
     if [ "$installnum" -lt "$actualnum" ]; then
	  echo "Fail Perms - $fn - Installed:$(echo $installedperms | cut -c $savedcut-),Actual:$(echo $actualperms)" >> $Results
	  ((scorecheck+=1))
	  start=5
	  continue
	 fi
     
	start="$((start+1))"
	startcut="$((startcut+1))"
	 
  done
 fi
   
 if grep "$fn" $TempDIR/RPMVA_status | grep '^.....U' >> /dev/null; then 
  echo "Fail Owner - $fn" >> $Results
  ((scorecheck+=1))
 fi

 if grep "$fn" $TempDIR/RPMVA_status | grep '^......G' >> /dev/null; then
  echo "Fail Group Owner - $fn" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
