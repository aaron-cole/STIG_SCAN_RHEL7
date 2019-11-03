#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

#STIG Identification
GrpID="V-71993"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-86617r5_rule"
STIGID="RHEL-07-020230"
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

echo "$(systemctl status ctrl-alt-del.target)" >> $Results

if [ "$(systemctl is-enabled ctrl-alt-del.target)" == "masked" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
