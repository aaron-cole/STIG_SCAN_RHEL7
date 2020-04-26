#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-71971"
GrpTitle="SRG-OS-000324-GPOS-00125"
RuleID="SV-86595r3_rule"
STIGID="RHEL-07-020020"
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

if [ -e /opt/isec/ens/threatprevention/bin/isecav ]; then
 echo "McAfee Endpoint Security for Linux Threat Prevention is installed and is a HIPS" >> $Results
 /opt/isec/ens/threatprevention/bin/isecav --version >> $Results
 echo "NA" >> $Results
else
 disregardlist="$(cat /etc/passwd | cut -f 1,3 -d":" | egrep ":[0-9]{1,3}$" | cut -f 1 -d":" | tr \\n \|)"
 disregardlist+="^__default__|^system_u"

 if semanage login -l | egrep -v "$disregardlist" | grep "unconfined_u" >> $Results; then
  echo "Non-Mapped Users Found make sure none are service accounts" >> $Results
  echo "Fail" >> $Results
 else
  semanage login -l >> $Results
  echo "Users are mapped correctly" >> $Results
  echo "Pass" >> $Results
 fi
fi
