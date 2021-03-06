#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.

#STIG Identification
GrpID="V-204613"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204613r603261_rule"
STIGID="RHEL-07-040630"
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

chkfiles="$(grep "^net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":"| sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^net.ipv4.icmp_echo_ignore_broadcasts" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^net.ipv4.icmp_echo_ignore_broadcasts" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 1 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^net.ipv4.icmp_echo_ignore_broadcasts" "$chkfile")" >> $Results
   else
    echo "Fail - Setting not found in $chkfile" >> $Results
   fi
  done
 else
  echo "Fail - $chkfile - too many entries" >> $Results
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk -v opf="$Results" '/^net.ipv4.icmp_echo_ignore_broadcasts/ {
	if($3 == 1) {
	 print "Pass - Setting Found in runtime -" $0 >> opf
	 } else {
	 print "Fail - Setting Not Found in runtime -" $0 >> opf
	 }
}'

if grep "Fail" $Results >> /dev/null; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
