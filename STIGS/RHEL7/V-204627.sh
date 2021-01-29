#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.

#STIG Identification
GrpID="V-204627"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204627r603261_rule"
STIGID="RHEL-07-040800"
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

if [ ! -e /etc/snmp/snmpd.conf ]; then
 echo "/etc/snmp/snmpd.conf does not exist" >> $Results
 echo "NA" >> $Results
else 
 if egrep "public|private" /etc/snmp/snmpd.conf | grep -v "^#" >> $Results; then
  echo "Fail" >> $Results
 else
  echo "No entries Found" >> $Results 
  echo "Pass" >> $Results
 fi
fi
