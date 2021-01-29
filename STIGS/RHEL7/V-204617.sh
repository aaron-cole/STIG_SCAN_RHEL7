#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

#STIG Identification
GrpID="V-204617"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204617r603261_rule"
STIGID="RHEL-07-040660"
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

chkfiles="$(grep "^net.ipv4.conf.all.send_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":" | sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^net.ipv4.conf.all.send_redirects" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^net.ipv4.conf.all.send_redirects" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 0 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^net.ipv4.conf.all.send_redirects" "$chkfile")" >> $Results
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
sysctl net.ipv4.conf.all.send_redirects | awk -v opf="$Results" '/^net.ipv4.conf.all.send_redirects/ {
	if($3 == 0) {
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
