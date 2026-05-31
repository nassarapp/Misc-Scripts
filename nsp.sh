#!/bin/bash
#Nassar Amin


WHITE='\033[1;371m'
LGHTGRN='\033[1;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
LGBLU='\033[1;34m'
CYAN='\033[0;36m'
NC='\033[0m'
bold=$(tput bold)
normal=$(tput sgr0)


cleanup()
{
  rm /tmp/nessus1x44r5.log 2> /dev/null
  rm /tmp/nessus2x44r5.log 2> /dev/null
  rm /tmp/nessus3x44r5.log 2> /dev/null
  rm /tmp/nessus4x44r5.log 2> /dev/null
  rm /tmp/blah.log 2> /dev/null
}

vulns()
{

  while IFS= read -r server; do
    printf "${WHITE}${bold}[*]${NC}${LGHTGRN}Server Found:${NC} %s\t${LGHTGRN}Port:${NC} %s\t${LGHTGRN}Protocol:${NC} %s\t${LGHTGRN}Host:${NC} ${YELLOW}%s${NC}\n" "$(echo $server | cut -d " " -f 4)" "$(echo $server | cut -d " " -f 2)" "$(echo $server | cut -d " " -f 6)" "$(echo $server | cut -d ":" -f 5)" | tee -a "$1"\.results

  done < /tmp/blah.log


}

helper()

{
printf "

${CYAN}
#     #  #####  ######
##    # #     # #     #
# #   # #       #     #
#  #  #  #####  ######
#   # #       # #
#    ## #     # #
#     #  #####  #



Nessus Service Parser v1.0
\tMarch 2020${NC}

"

  echo -e "${LGBLU}Please use the -f flag and specify a file${NC}"
  echo -e "${LGBLU}$0 -f abc123-perimeter-scan.nessus${NC}"
  exit
}

formatting()
{


cat /tmp/nessus1x44r5.log | sed -e 's/<ReportHost name=\"/\'$'\nHost Found: /g' | sed -e s'/"><HostProperties>//g'| sed -e s"/<ReportItem port=\"/Port: /g" | sed -e s'/svc_name=\"/Service: /g' | sed -e s'/protocol=\"/Protocol: /g' | sed -e s'/severity=.*//g' | sed -e 's/\"/\t/g' >> /tmp/nessus2x44r5.log
echo "" >> /tmp/nessus2x44r5.log #echo a new line to the end of the file

}

display_function()
{
  while IFS= read -r line; do
    if [[ $line =~ "Host Found:" ]];
    then
      va=$line

    fi
    if [[ $line =~ "Port:" ]];
      then
        echo "$line $va" | sed s'/ Found//g' | sed s'/Port: 0	 Service: general.*//g' | sed -r '/^\s*$/d'	 >> /tmp/nessus3x44r5.log

      fi
  done < /tmp/nessus2x44r5.log
  cat /tmp/nessus3x44r5.log | sort | uniq >> /tmp/nessus4x44r5.log
  while IFS= read -r vuln; do #Below should really be in an array and a for loop to iterate through each entry for a match
    if [[ $vuln =~ "mysql"|"mssql"|"postgres"|"oracle"|"sybase"|"ssh"|"pptp"|"kerberos"|"openvpn"|"kpasswd"|"microsoft-ds"|"smb"|"telnet"|"cisco"|"ike"|"ftp"|"tftp"|"pop"|"smtp"|"imap"|"sip"|"snmp"|"ldap"|"rdp"|"cifs"|"vnc"|"socks"|"ajp13"|"netbios"|"tacacs"|"login"|"xdmcp"|"rpc"|"rwho"|"X11"|"webmin"|"novell"|"finger" ]];
      then
        echo -e "$vuln\t${RED}${bold}Danger!!!"${NC} >>/tmp/blah.log
      else
        echo -e "$vuln">>/tmp/blah.log
    fi
      done < /tmp/nessus4x44r5.log

}

scanner()

{

if [[ "$1" =~ "<ReportHost name=" ]] || [[ "$1" =~ "<ReportItem port=" ]];  #finds the hostname first and open ports and services after, line by line.
  then
      echo "$1" >> /tmp/nessus1x44r5.log
  fi

}

if [ $# -lt 1 ]
then
    helper
    exit
  fi

while getopts ":f:" c; do
  case $c in
    f)
    if [ -f $OPTARG ]; then

       echo -e "\n"
       echo -e "${WHITE}${bold}[*]${NC}${LGHTGRN}Scanning${NC} $OPTARG\n\n"
       cleanup

    else
       echo "File $OPTARG does not exist."
       exit
    fi
    num=$(wc -l $OPTARG  | cut -d " " -f 1)
    echo -e "${WHITE}${bold}[*]${NC}${LGHTGRN}Total lines to read:${NC} $num"

    LINEREAD=0
    while IFS= read -r line; do

    (( LINEREAD++ ))    #increment lines read
    scanner "$line"

    echo -ne "${WHITE}${bold}[*]${NC}${LGHTGRN}Lines Read:${NC} $LINEREAD\033[0K\r"

    done < $OPTARG
    ;;

  *)
    helper

    ;;
  esac
  echo -e "${WHITE}${bold}[*]${NC}${LGHTGRN}Total lines read:${NC} $LINEREAD"
  d=$(date '+%F_%H:%M:%S')  #Time stamp
  echo -e "\n"
  echo -e "${WHITE}${bold}[*]${NC}${LGHTGRN}Filename saved as:${NC} $OPTARG.$d.results\n"
  sleep 1
  echo -e "${WHITE}${bold}[*]${NC}${LGHTGRN}Formatting output...${NC}\n"
  sleep 1
  formatting
  display_function
  vulns $OPTARG.$d
  cleanup
done
