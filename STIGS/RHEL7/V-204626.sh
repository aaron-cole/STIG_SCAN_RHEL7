#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.

#STIG Identification
GrpID="V-204626"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-204626r603261_rule"
STIGID="RHEL-07-040750"
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

if grep " nfs" /etc/fstab >> $Results; then
 if [[ "$(grep " nfs" /etc/fstab | grep "sec=krb5:krb5i:krb5p")" ]] && [[ ! "$(grep " nfs" /etc/fstab | egrep "sec=sys|:sys")" ]]; then
  echo "Pass" >> $Results
 else
  echo "Security Not Configured" >> $Results
  echo "Fail" >> $Results
 fi
elif mount | grep nfs | egrep -v "on /proc|sunrpc on"  >> $Results; then
 if mount | grep " nfs" | egrep -v "on /proc|sunrpc on" | grep "sec=krb5:krb5i:krb5p" >> $Results; then
  echo "Pass" >> $Results
 else
  echo "Security Not Configured" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "No NFS mounts configured" >> $Results
 echo "Pass" >> $Results
fi
