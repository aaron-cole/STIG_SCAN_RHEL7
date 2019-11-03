#!/bin/sh

#STIG Identification
GrpID=""
GrpTitle=""
RuleID=""
STIGID=""
Results="./Results/$STIGID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results

#Checks - pick 1 or combine
##########################################################
# For All OSs
##########################################################

###########################
#          Manual         #
###########################
Command_to_produce_results >> $Results
echo "Manual" >> $Results

###########################
#     Check if exists     #
###########################
fdexists="/etc/shells"

if [ ! -e $fdexists ]
then
 echo "$fdexists does not exist - Fail" >> $Results
else 
 
 echo "$(ls -l $fdexists)" >> $Results
 echo "Pass" >> $Results
fi

#################################
# Check Multi Owner of File/dir #
#################################
#File or Directory to check
file="/etc/securetty"

#Check
OwnerID="$(perl -le'print((stat shift)[4])' $file)"
if [ -f $file ]
then
 OwnerID2="$(ls -lL $file | awk '{print $3}')"
 ls -lL $file >> $Results
elif [ -d $file ]
then
 OwnerID2="$(ls -ld $file | awk '{print $3}')"
 ls -ld $file >> $Results
else 
 
 echo "Not a file or dir" >> $Results
fi

echo "Perl stat for UID is $OwnerID" >> $Results
echo "awk Statment for user is $OwnerID2" >> $Results

case "$OwnerID" in
	0|2|3|root|bin|sys) echo "Pass"  >> $Results;;
	*) echo "Fail" >> $Results;;
esac

#################################
# Check Owner of multi File/dir #
#################################
#List to be checked
files="$(find / -type f -name "*.mib" )"

for f in $files
do
#Check
OwnerID="$(perl -le'print((stat shift)[4])' $f)"
if [ -f $f ]
then
 OwnerID2="$(ls -lL $f | awk '{print $3}')"
elif [ -d $f ]
then
 OwnerID2="$(ls -ld $f | awk '{print $3}')"
else 
 
 echo "Not a file or dir" >> $Results
fi

case "$OwnerID" in
	0|2|3|root|bin|sys) echo "Pass - $f - $OwnerID"  >> $Results;;
	*) echo "Fail - $f - OwnerID" >> $Results;;
esac
done

if grep "Fail" $Results >> /dev/null
then
 echo "Fail" >> $Results
else 
 
 echo "Pass" >> $Results
fi

#################################
# Check Multi Group Owner of File/dir #
#################################
#File or Directory to check
file="/etc/securetty"

#Check
GOwnerID="$(perl -le'print((stat shift)[5])' $file)"
if [ -f $file ]
then
 GOwnerID2="$(ls -lL $file | awk '{print $4}')"
 ls -lL $file >> $Results
elif [ -d $file ]
then
 GOwnerID2="$(ls -ld $file | awk '{print $4}')"
 ls -ld $file >> $Results
else 
 
 echo "Not a file or dir" >> $Results
fi

echo "Perl stat for GID is $GOwnerID" >> $Results
echo "awk Statment for group is $GOwnerID2" >> $Results

case "$GOwnerID" in
	0|2|3|root|bin|sys) echo "Pass"  >> $Results;;
	*) echo "Fail" >> $Results;;
esac

#######################################
# Check Group Owner of multi File/dir #
#######################################
#List to be checked
files="$(find / -type f -name "*.mib" )"

for f in $files
do
#Check
GOwnerID="$(perl -le'print((stat shift)[5])' $file)"
if [ -f $f ]
then
 GOwnerID2="$(ls -lL $file | awk '{print $4}')"
elif [ -d $f ]
then
 GOwnerID2="$(ls -lL $file | awk '{print $4}')"
else 
 
 echo "Not a file or dir" >> $Results
fi

case "$GOwnerID" in
	0|2|3|root|bin|sys) echo "Pass - $f - $GOwnerID"  >> $Results;;
	*) echo "Fail - $f - GOwnerID" >> $Results;;
esac
done

if grep "Fail" $Results >> /dev/null
then
 echo "Fail" >> $Results
else 
 
 echo "Pass" >> $Results
fi

#################################
#  Check Mode of 1 File or dir  #
#################################
#File to check
file="/etc/securetty"
filemode="$(perl -le'printf "%o\n",(stat shift)[2] & 07777' $file)"
checkmode="755"

#Check
if [ $filemode -le $checkmode ]
then
 echo "Perl stat for $file is $filemode and less than or equal to $checkmode" >> $Results
 echo "Pass" >> $Results
else 
 
 echo "Perl stat for $file is $filemode and not less than or equal to $checkmode" >> $Results
 echo "Fail" >> $Results
fi

#################################
#   Check Mode of multi Files   #
#################################
#File or Directory to check
files="/etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/.login "
scorecheck=0
checkmode="444"

for file in $files; do
 if [ -e $file ]; then
  filemode="$(perl -le'printf "%o\n",(stat shift)[2] & 07777' $file)"
  if [ $filemode -le $checkmode ]; then
   echo "$file is $filemode and less than or equal to $checkmode" >> $Results
  else
   echo "$file is $filemode and not less than or equal to $checkmode" >> $Results
   ((scorecheck+=1))
  fi
 else
  echo "$file does not exist" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi

##########################################################
#HPUX Specific
##########################################################

###########################
#   HPUX Base for both    #
###########################

#For Trusted Mode

  echo "Pass" >> $Results
  
  echo "Fail" >> $Results

#For SMSE mode
else 
  

  echo "Pass" >> $Results


  echo "Fail" >> $Results
fi

#################################
#          Audit Check          #
#################################
auditfile="/etc/rc.config.d/auditing"
auditcheck="moddac"

if grep -i audevent_args1 $auditfile | grep "-e $auditcheck" >> $Results
then
 echo "Pass" >> $Results
else 
 
 echo "Fail" >> $Results
fi
  
##########################################################
#RHEL Specific
##########################################################

#######################################
# RHEL Check Single Owner of File/dir #
#######################################
#File or Directory to check
file="/etc/group"
chkuser="root"

ls -l $file >> Results

if [ "$(stat -c %U $file)" == "$chkuser" ]
then 
 echo "Pass" >> $Results
else 
  
 echo "Fail" >> $Results 
fi

#################################
# RHEL Check Group Owner of File/dir #
#################################
#File or Directory to check
file="/etc/group"
chkuser="root"

ls -l $file >> Results

if [ "$(stat -c %G $file)" == "$chkuser" ]
then 
 echo "Pass" >> $Results
else 
  
 echo "Fail" >> $Results 
fi


#################################
# RHEL Check Group Owner of File/dir #
#################################
#File or Directory to check
file="/etc/group"
checkmode="644"

ls -l $file >> Results

if [ "$(stat -c %a $file)" == "$checkmode" ]
then 
 echo "Pass" >> $Results
else 
  
 echo "Fail" >> $Results 
fi

#################################
#     RHEL Mount Check          #
#################################
mountcheck="on /var "

if mount | grep $mountcheck >> $Results
then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi

#################################
#     RHEL Service Check        #
#################################
servicecheck="autofs"

if [ "$(service $servicecheck status | grep "is running." >> $Results)" ] || [ "$(chkconfig $servicecheck --list | grep -e "\<[1-5]\>:on" >> $Results)" ] 
then 
 echo "Fail" >> $Results
else 
  service $servicecheck status >> $Results
  chkconfig $servicecheck --list >> $Results
 echo "Pass" >> $Results 
fi

#################################
#       RHEL RPM Check          #
#################################
rpmname="libreswan"

if rpm -qi $rpmname >> $Results
then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi

#################################
#  RHEL RPM and setting Check   #
#################################
rpmname="GConf2"
checkvalue="true"

if rpm -qi $rpmname >> $Results; then 
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable)" == "$checkvalue" ]; then
  echo "Pass" >> $Results 
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Package not installed" >> $Results
 echo "Pass - NotApplicable" >> $Results
fi


#################################
#  Check ACL of 1 File or dir   #
#################################
#File or Directory to check
file="/etc/securetty"

#Check
findACLHFS="$(find $file -acl opt)"
findACLvxfs="$(find $file -aclv opt)"
fileACL="$(getacl $file)"
#fileACLHFS="$(lsacl -l $file)"

if ls -lLd $file | awk '{print $1}' | grep "+" >> $Results
then
 echo $fileACL >> $Results
 echo "Fail" >> $Results
else 
 
 echo $fileACL >> $Results
 echo "Pass"  >> $Results
fi

#################################
#  Check ACL of Files or dirs   #
#################################
files="/etc/inetd.conf /etc/xinetd.conf"
scorecheck=0

for f in $files
do
 if [ -e $f ]
then
  fileACL="$(getacl $file)"
  if ls -lLd $f | awk '{print $1}' | grep "+" >> $Results
then
   echo "$f - $fileACL - Fail" >> $Results
   ((scorecheck+=1))
  else 
 
   echo "$f - $fileACL - Pass" >> $Results
  fi
 else 
 
  echo "$f Does not exist" >> $Results
 fi  
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi

#################################
#   FILEMODE Multi fileCheck    #
#################################
scorecheck=0
chkowner=7
chkgroup=5
chkother=5
files="/etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/.login "

for file in $files
 ls -alL $file >> $Results
 start=1
 filemode="$(perl -le'printf "%o\n",(stat shift)[2] & 07777' $file)"
 while [ "$start" -le ${#filemode} ] ; do
  if [ ${#filemode} = 4 ] && [ "$start" = 1 ]; then
   start="$((start+1))"  
   continue
  fi
  if [ ${#filemode} = 4 ]; then
   case "$start" in
    2)effectivestart=1;;
    3)effectivestart=2;;
    4)effectivestart=3;;
   esac
  else
   effectivestart="$start"
  fi

  checknum=$(echo $filemode | cut -c $start)
 
  case "$effectivestart" in
   1) if [ $chkowner -lt $checknum ]; then
       ((scorecheck+=1))
      fi
      start="$((start+1))" ;;
   2) if [ $chkgroup -lt $checknum ]; then
       ((scorecheck+=1))
      fi
      start="$((start+1))" ;;
   3) if [ $chkother -lt $checknum ]; then
       ((scorecheck+=1))
	  fi
      start="$((start+1))" ;;
  esac
 done  
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi 

