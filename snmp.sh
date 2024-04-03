#!/bin/bash

# Fail on unset var usage
set -o nounset
# Prevents errors in a pipeline from being masked
set -o pipefail

ARG_IP=""
ARG_COMMUNITY_FILE="community.txt"
ARG_LOGFILE="snmp_log.txt"

COMMUNITY=()

# Print and log
function log() {
  echo "$1" | tee -a "$ARG_LOGFILE"
}

# Community Strings discovery for SNMP version 2c, check if SNMP version 1 is enabled and if NO_AUTH is available version 3.
function brute_force_community_strings {
	local TEST_OID="1.3.6.1.2.1.1.1.0" #sysDescr OID for read testing

	log "[INFO] Brute force community strings for SNMP Version 2c"
	for community_string in `cat $ARG_COMMUNITY_FILE`
	do
		snmpget -t 1 -r 0 -v 2c -c "$community_string" $ARG_IP $TEST_OID > /dev/null 2>&1
		if [ $? -eq 0 ];
		then
			log "[INFO] SNMP Version 2c with Community String { $community_string } is available!"
			COMMUNITY+=("$community_string")
		fi
	done

	if [ ${#COMMUNITY[@]} -eq 0 ];
	then
		log "[ERROR] No Valid Community Strings Found" 
		exit 1
	fi

	log "[INFO] Test first Community Strings for SNMP Version 1"
	snmpget -t 1 -r 0 -v 1 -c ${COMMUNITY[0]} $ARG_IP $TEST_OID > /dev/null 2>&1
	if [ $? -eq 0 ];
	then
		log "[INFO] SNMP Version 1 with Community String { ${COMMUNITY[0]} } is available!"
	fi

	log "[INFO] Check if NO_AUTH is available for SNMP Version 3"
	snmpget -t 1 -r 0 -v 3 -l noAuthNoPriv -u usr-none-none $ARG_IP $TEST_OID > /dev/null 2>&1
	if [ $? -eq 0 ];
	then
		log "[INFO] SNMP Version 3 with NO_AUTH Available!"
	fi

	log "[INFO] Valid Community Strings for SNMP Version 2c"
	log "${COMMUNITY[*]}"
}

# Get basic target information via SNMP.
function get_basic_info {
	log "[INFO] Get OS Info"
	snmpget -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.1.1.0 >> $ARG_LOGFILE 2>/dev/null
	snmpget -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.1.5.0 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get IP Addresses"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.4.20.1.1 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get System Processes"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.25.1.6.0 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get Running Programs"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.25.4.2.1.2 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get Processes Path"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.25.4.2.1.4 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get Storage Units"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.25.2.3.1.4 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get Software Name"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.25.6.3.1.2 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get User Accounts"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.4.1.77.1.2.25 >> $ARG_LOGFILE 2>/dev/null

	log "[INFO] Get TCP Local Ports"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.2.1.6.13.1.3 >> $ARG_LOGFILE 2>/dev/null
}

# Check write permissions for each discovered Community String.
function check_write_permission {
	local TEST_OID="1.3.6.1.2.1.1.4.0" #sysContact OID for write testing 1.3.6.1.2.1.1.4.0
	local backup=`snmpget -Oqv -t 1 -r 0 -v 2c -c ${COMMUNITY[0]} $ARG_IP $TEST_OID | grep -oP '"\K[^"\047]+(?=["\047])'`

	log "sysContact OID original value is { $backup }"

	for community_string in "${COMMUNITY[@]}"
	do
		snmpset -t 1 -r 0 -v 2c -c $community_string $ARG_IP $TEST_OID str "test" > /dev/null 2>&1
		if [ $? -ne 0 ];
		then
			log "[ERROR] Target $ARG_IP with Community String { $community_string } does NOT have Write Permission!"
		else
			log "[INFO] Community String { $community_string } has Write Permission!"
			if [ -z "$backup" ];
			then
				snmpset -t 1 -r 0 -v 2c -c $community_string $ARG_IP $TEST_OID str "" > /dev/null 2>&1
			else 
				snmpset -t 1 -r 0 -v 2c -c $community_string $ARG_IP $TEST_OID str "$backup" > /dev/null 2>&1
			fi
		fi		
	done
}

# Check if NET-SNMP-EXTEND-MIB::nsExtendObjects (1.3.6.1.4.1.8072.1.3.2) is present to achieve RCE.
function check_rce {
	log "[INFO] Check for nsExtendObjects module"
	snmpwalk -v 2c -c ${COMMUNITY[0]} $ARG_IP 1.3.6.1.4.1.8072.1.3.2 | grep INTEGER > /dev/null 2>&1

	if [ $? -ne 0 ];
	then
		log "[ERROR] Target $ARG_IP NOT Exploitable!"
		return
	fi

	log "[INFO] Target $ARG_IP might be Exploitable!"
}

# Print help message
function print_help() {
	cat << EOF
Usage: snmp.sh [--help] --ip IP 

Bash script to discovery valid SNMP Community Strings, dump information, check write permissions and check for possible RCE via SNMP.

Arguments:
  --help                   Show this help message and exit
  --ip IP                  Target IP to test
EOF
	exit 1
}

# Script entrypoint
function main {
	# Analyze arguments
	while [[ $# -gt 0 ]]; do
		case $1 in
			--ip)
				ARG_IP="$2"
				rm -rf $ARG_LOGFILE
				brute_force_community_strings
				get_basic_info
				check_write_permission
				check_rce
				shift
				shift
			;;
			--help)
				print_help
			;;
			--*)
				print_help
			;;
			*)
				print_help
			;;
		esac
	done
}

main "$@"
