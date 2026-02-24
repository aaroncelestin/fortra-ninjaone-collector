#!/usr/bin/env bash
# shellcheck disable=SC2155,SC2119,SC2004,SC2053,SC2027,SC2086,SC2120,SC2091,SC2001,SC2184
# Aaron Celestin aaron.celestin@fortra.com
set -o pipefail
declare InstallScriptVersion='0.2.26_20260217'
declare -r NC=$(tput sgr0)
declare -r RED=$(tput setaf 1)
declare -r GRE=$(tput setaf 2)
declare -r YEL=$(tput setaf 3)
declare -r BLU=$(tput setaf 4)
declare -r MAG=$(tput setaf 5)
declare -r CYA=$(tput setaf 6)
# Installs and configures the NinjaOne log collector script into a systemd service on a Linux system.
# The script sets up necessary environment variables, creates a configuration file, and ensures the service starts on boot.
# Usage: sudo bash install_ninjaone_collector.sh
declare AppFile="ninjaone_collector.sh" # path to the main collector script app
declare AppName=$(basename "$AppFile" .sh) # name of the main collector script app without .sh extension
declare FirstRun=true
declare ClientId=""
declare ApiEndpoint='https://us2.ninjarmm.com/v2/activities'
declare ConfigDir="/etc/${AppName,,}"
declare ConfigPath="${ConfigDir}/app.conf"
declare StateFile="$ConfigDir/.lastrun.state"
declare TargetLogPath="/var/log/${AppName}"
declare TargetLogFormat="YYMMDD"
declare Uninstall=false
declare _UUID_REGEX='^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$'
declare _NUM_REGEX='^[0-9]+$'
declare _URL_REGEX='^(https://[^\s/$.?#].[^\s]*$'
declare _FILENAME_REGEX='[a-zA-Z0-9_\-. ]+'
declare _DIRNAME_REGEX='^\/?[\w\/\-.+:_]+'
declare _DATE_FORMAT_REGEX='^(YYYYMMDD|YYYY-MM-DD|MMDDYYYY|MM-DD-YYYY|DDMMYYYY|DD-MM-YYYY|YYMMDD|YY-MM-DD|DDMMYY|DD-MM-YY|MMDDYY|MM-DD-YY)$'
#################### ADVANCED CONFIGURATION OPTIONS ##########################
declare -i MaxLogFilePercentage=70 # max file size percentage of total disk space before exiting script with error
declare -i PageSize=200
declare -ir MaxPageSize=1000
declare -i MaxRetries=5
declare -i RetryDelay=10
declare -i StartDateTime=$(( $(date +%s) - 86400 )) # start datetime in seconds one day prior from now
declare GetAllAvailableLogs=false
declare StartNow=false
declare -i StartAtId=200 # first run default newest activity ID
declare RotationInterval='daily'
declare SigKey=$(openssl rand -hex 32 2>/dev/null) # generate a random signature key for this installer
declare -i StartDelay=10 # delay in seconds before starting collection on first run to allow user to stop the script if needed
declare FilterFile="" # path to filter file, if any
declare SysConfDir="/var/lib/$AppName"
declare CredentialFile=".apiinfo" # default credential file name
declare SysConfSDir="$SysConfDir/.ssl"
declare CredentialPath="$SysConfSDir/$CredentialFile" # default full path to credential file
declare -a ClassFilters TypeFilters StatusFilters
########################## SYSTEMD SERVICE OPTIONS ###########################
declare UseNativeJsonParser=false
declare -i RotateTimer=30 # log rotation timer in days
declare -i MaxAge=60 # max age in days to keep old log files
declare -i RunInterval=15 # interval in minutes to run the collector
declare -i RunOnBootTime=5 # time in minutes to wait after boot before first run
declare TimerFile="/usr/lib/systemd/system/$AppName.timer"
declare ServiceFile="/lib/systemd/system/$AppName.service"
declare RotationFile="/etc/logrotate.d/$AppName"
declare -i MenuW=$(( $(tput cols) * 3/4 ))
declare -a ActivityClassFilters=(
    USER
    DEVICE
    SYSTEM
    ALL
)
declare -a ActivityTypeFilters=(
    ACTIONSET
    ACTION
    CONDITION
    CONDITION_ACTIONSET
    CONDITION_ACTION
    ANTIVIRUS
    PATCH_MANAGEMENT
    TEAMVIEWER
    MONITOR
    SYSTEM
    COMMENT
    SHADOWPROTECT
    IMAGEMANAGER
    HELP_REQUEST
    SOFTWARE_PATCH_MANAGEMENT
    SPLASHTOP
    CLOUDBERRY
    CLOUDBERRY_BACKUP
    SCHEDULED_TASK
    RDP
    SCRIPTING
    SECURITY
    REMOTE_TOOLS
    VIRTUALIZATION
    PSA
    MDM
    NINJA_REMOTE
    NINJA_QUICK_CONNECT
    NINJA_NETWORK_DISCOVERY
    NINJA_BACKUP
    NINJA_TICKETING
    KNOWLEDGE_BASE
    RELATED_ITEM
    CLIENT_CHECKLIST
    CHECKLIST_TEMPLATE
    DOCUMENTATION
    MICROSOFT_INTUNE
    DYNAMIC_POLICY        
)

########################## USAGE AND TUI FUNCTIONS ###########################
function segm () { local -i w=$1; for ((i=0;i<$w;i++)); do echo -en '-'; done; echo; }
function degm () { local -i w=$1; for ((i=0;i<$w;i++)); do echo -en '='; done; echo; }
function install_collector_title () { 
    local eline='+============================================================================+'
    echo -e "$eline"
    printf '%-18s %32s %21s\n' "|" "Ninja One API Log Collector Installer" "|" 
    printf '%-15s %32s %29s\n' "|" "Version: $InstallScriptVersion" "|"
    echo -e "$eline"; 
}
function install_collector_usage () {
    install_collector_title
    local -i exit_code=${1:-0}
    local -i scrw=$MenuW
    col1=$(( scrw * 2/80))
    col2=$(( scrw * 11/80))
    col3=$(( scrw * 67/80)) 
    local desc="This script installs an application that collects NinjaOne Activity logs from NinjaOne's API endpoint and saves them to a directory to send to a SIEM. When started, the default log collection datetime is 24 hours before the start time. You may override this by using the '--start-now' or '--start-at-datetime SOMEDATE' switches. Most configuration options can be changed with command line \
switches. Any configuration options set via cmd-line switches are stored in a config file for future runs. See the OPTIONS section below for which options can be set. You may also specify a custom configuration file for the script to read your custom configuration variables and an optional filter file that will be used to build log filters by ActivitiyStatus. Other filters can be added interactively. See the \
FILTERS section below for more information. NinjaOne API access requires the following script variables to be set: Client ID, Client Secret, and API Endpoint. You will be prompted to enter the Client ID and Client Secret during installation if not set in the environment or credential file. You may set the API auth variables in \
a file at ~/.ninjaone_collector and change the permissions to 0600 before running the script."
    echo
    echo -e "DESCRIPTION:"
    fold -w $scrw -s <<< "$desc"
    local nstate="The script will create a state file to track the last-stored log activity ID. This file is located at: '$StateFile'. Do not delete this file unless you want to re-collect all logs from the beginning. If you want to change the starting activity ID, you may edit this file or use the --start-at-actid option on the command line."
    local nconff="The script will also create a configuration file at: '$ConfigPath' to store your configuration variables for future runs. You can change any variables in the configuration file after installation and the script will use them on the next run. This feature is useful for adding or removing filters. However, log rotation and systemd service settings can only be modified by running the reinstallion \
script again. Note these in the options below: NOT Config file updateable."
    local nfilt="You will be prompted to optionally enter filters for the NinjaOne Logs that can be applied on each call. There are three types of filters for NinjaOne logs: ActivityType, ActivityClass and ActivityStatus. There are only 4 ActivityClass filters: SYSTEM, USER, DEVICE and ALL. There are 37 ActivityType filters and there are 673 ActivityClass filters. For more informtion on filters see NinjaOne's API \
documentation here: https://app.ninjarmm.com/apidocs-beta/core-resources/operations/getActivities. There is a limit of about 100 filters you can apply at a time. If you do not see any logs after applying filters, try reinstalling with different filters or you may modify the configuration file manually to add/remove filters."
    echo -e "\nFILTERS:"
    fold -w $scrw -s <<< "$nfilt"
    echo -e "\nCONFIGURATION LIMITATIONS:"
    fold -w $scrw -s <<< "$nconff"
    echo -e "\nSTATE FILE:"
    fold -w $scrw -s <<< "$nstate"
    local ncreds="You may set the API auth variables: ClientId and ClientSecret in a file, although this is not recommended. Be sure to set the permissions of the creds file to 0600 before running the script. Then call the installer script with the '--credential-file' option pointing to the path to the credential file."
    echo -e "\nAPI CREDENTIALS:"
    fold -w $scrw -s <<< "$ncreds"
    local ninst="This script must be run with sudo privileges (i.e. sudo bash scriptname.sh) to install the systemd service and timer. If you cannot use sudo privileges, you may set up this app as a cron job instead of as a systemd service."
    echo -e "\nINSTALLATION:"
    fold -w $scrw -s <<< "$ninst"
    echo -e "\nUNINSTALLATION:"
    local nuins="To uninstall the collector, run the script with the '--uninstall' option. This will stop and disable the systemd service and timer, remove the service and timer files, and delete the configuration and state files. It will not delete the log files in the target directory."
    fold -w $scrw -s <<< "$nuins"
    echo -e "\nACCEPTED DATE FORMATS:"
    local ndates1="The script uses GNUs date utility to parse many string date formats, all of which are too numerous to list here. All separators are supported: (-|.|_|/|,), spaces are allowed, dates can be in any order and the month can be strings like 'January', 'Feb', 'Mar', etc. Strongly recommend you use ZULU time for Timezones unless you know what you are doing."
    local ndates2="If you are not sure about the date format, try the simplest format: 'September 27, 2025 3:00PM'. The script will use the date utility to parse the string and set the start datetime. For more on date formats, highly recommend you read the GNU documentation here: https://www.gnu.org/software/coreutils/manual/html_node/Date-input-formats.html"
    fold -w $scrw -s <<< "$ndates1"
    fold -w $scrw -s <<< "$ndates2"
    echo -e "\nEXAMPLES:"
    local bn=$(basename "$0")
    local -a examples=(
        "sudo bash $bn --start-at-datetime 'Sept 25, 2025 3:00PM' --page-size '500' --target-format 'DD-MM-YY' --filter-file './filters.txt'"
        "sudo $0 --url-endpoint 'https://us2.ninjarmm.com/v2/activities' --target-directory '/var/logs/ninjaone' --filter-file './filters.txt'"
        "sudo bash $bn --config-file './custom_config.conf' --max-log-age '90' --log-rotation-interval 'weekly' --log-rotate-timer '12' --run-interval '30' "
        "sudo $0 --credential-file '/path/to/credsfile' --config-file './custom_config.conf' --force-first-run --run-onboot-time '10'"
        "$bn --help"
    )
    for example in "${examples[@]}"; do
        echo -e "\$_> $example\n" | fold -w $scrw -s
    done
    local note5="NOTE: Most special characters entered for filenames or paths will be ignored or removed IMMEDIATELY to avoid issues with script operation. Only alphanumeric characters and the following characters are allowed:[ / . - _ : + ]"
    echo; echo -e "$note5" | fold -w $scrw
    echo -e "\nSERVICE AND TIMER MANAGEMENT:"
    echo -e "Service Control Options:\n\t'sudo systemctl start|stop|restart|status $AppName.service'"
    echo -e "Service Management Options:\n\t'sudo systemctl enable|disable $AppName.service'"
    echo -e "Timer Control Options:\n\t'sudo systemctl start|stop|restart|status $AppName.timer'" 
    echo -e "Timer Management Options:\n\t'sudo systemctl enable|disable $AppName.timer'"
    echo -e "\nOPTIONS:" 
    local -a options=(
    "-u,--url-endpoint,Specify the NinjaOne API endpoint URL. Default is '$ApiEndpoint'. This can be changed in the config file later."
    "-k,--client-id,Specify your NinjaOne API Client ID. You will be prompted to enter this if not set in the environment or credential file."
    "-i,--run-interval,Specify the interval in minutes between runs of the service that starts the collector. Default is '15'. NOT Config file updateable."
    "-b,--run-onboot-time,Specify the time in minutes to wait after boot before first run of the service that starts the collector. Default is '5'. NOT Config file updateable."
    "-g,--max-log-age,Specify the max age in days to keep old log files. Default is '60'. NOT Config file updateable."
    "-y,--log-rotation-interval,Specify the log rotation interval. Default is 'daily'. NOT Config file updateable."
    "-z,--log-rotate-timer,Specify the log rotation timer in days. Default is '30'. NOT Config file updateable."
    "-c,--config-file,Specify the path to your intitial configuration file. Once installed location will be '/etc/$AppName/app.conf'."
    "-s,--start-at-actid,Specify the start activity ID to begin collection at. Default start activity ID is 1 on the FirstRun."
    "-m,--start-at-datetime,Specify the start datetime to begin collection at. See notes for accepted formats. Default start datetime is 1 day ago."
    "-n,--start-now,Specify to begin collection now at installation time and ignore any previous logs."
    "-j,--get-all-logs,Get all logs from the beginning of time. This will cause the collector to run for a long time."
    "-p,--page-size,Specify the number of logs to retrieve per API call. Default is 200. Max is 1000. Config file updateable."
    "-t,--target-directory,Specify the directory to save collected logs. Default is '$TargetLogPath'. Config file updateable."
    "-l,--target-format,Specify the log file date format. Default is 'YYYYMMDD'. Config file updateable."
    "-f,--filter-file,Specify the path to a filter file containing a list of custom filters. Config file updateable."
    "-a,--credential-file,Specify the path to your credential file. Default is '$CredentialPath'. Config file updateable."
    "-r,--force-first-run,Force the collector to run in FirstRun mode, backing up existing user config if it exists. Config file updateable."
    "-x,--uninstall,Uninstall the collector. This will stop-disable-delete the systemd service and timer and remove all files including auth config and state artefacts."
    "-d,--debug,Enable debug mode for verbose output."
    "-h,--help,Display this help message and exit." )
    if (( $(tput cols) < 80 )); then
        echo -e "${RED}ERROR${NC} - Terminal width is too narrow to display the help menu. Please increase the width of the terminal."
        exit 1
    elif (( $(tput cols) < 110 )); then
        for opt in "${options[@]}"; do
            IFS=, read -r short long desc <<< "$opt"
            echo -e "[Short]:$short\n[LongOpts]:$long\n[Description]:$desc\n\n"
        done
    else
        s='Shrt'; l='Long Opts'; d='Description'
        echo -en "+$(segm ${col1})+$(segm ${col2})+$(segm ${col3})+"; echo
        printf "|%${col1}s|%-${col2}s|%-${col3}s|\n" "${s:0:${col1}}" "${l:0:${col2}}" "${d:0:${col3}}"
        echo -en "+$(segm ${col1})+$(segm ${col2})+$(segm ${col3})+"; echo
        for opt in "${options[@]}"; do
            IFS=, read -r short long desc <<< "$opt"
            printf "|%${col1}s|%-${col2}s|%-${col3}s|\n" "${short:0:${col1}}" "${long:0:${col2}}" "${desc:0:${col3}}" 
        done
        echo -en "+$(segm ${col1})+$(segm ${col2})+$(segm ${col3})+"; echo
    fi
    return $exit_code
}
####################### ENCRYPTION AND CREDENTIAL MGMT FUNCTIONS ##########################
function check_pre_requisites () {
    # check pre-requisutes: openssl, rsyslog, logrotate, if available
    local -A reqs_website=( 
        [logrotate]='https://github.com/logrotate/logrotate' 
        [openssl]='https://docs.openssl.org/master/man1/openssl/'
        #[rsyslog]='https://www.rsyslog.com/doc/index.html' 
    )
    local -i fail=0
    for reqs in "${!reqs_website[@]}"; do
        if [[ -z $(which $reqs 2>/dev/null) ]]; then
            fail=$(( fail + 1 ))
            echo -e "${RED}ERROR${NC} - Pre-requisite: [$reqs] was not found on this system.\nPlease install:[$reqs] and try again."
            echo -e "Pre-requisite website: '${reqs_website[$reqs]}'"
            echo -e "Potential install commands: \n\tapt|yum|dnf install $reqs"
            echo
        fi
    done
    if (( fail >= 1 )); then { Uninstall=true; echo "FATAL - Installation failed. Any changes will be rolled back."; return 1; }
    else { return 0; }
    fi
}
function convert_date_to_epoch () {
    local date_string="$*"
    date --date="$date_string" +%s
}
# this function encrypts a string using AES-256-CBC or DES3 depending on the version of OpenSSL installed using SigKey as the passphrase
function encrypt_sk () { 
    local in="$*"
    echo "$in" | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass "pass:$SigKey"
}
function get_clientid_from_user () {
    echo
    segm $MenuW
    echo -e "${YEL}GET CLIENT ID${NC}"
    segm $MenuW
    read -rp "Please enter the Client ID: " input
    if [[ -n "$input" && ${#input} -ge 26 ]]; then
        ClientId=$(tr -dc '[:alnum:]' <<< "$input") &&  echo -e "${GRE}OKAY${NC} - client ID: [$ClientId] was added."
        update_config_file 'CLIENT_ID' "${ClientId}" "$ConfigPath" && return 0
    else
        echo -e "${RED}ERROR${NC} - Invalid access key:[$ClientId] was entered. Check your Client ID and try again."
        return 1
    fi
}
function get_clientsecret_from_user () {
    local input
    local -i chars=0
    echo
    segm $MenuW
    echo -e "${YEL}GET SECRET KEY${NC}"
    segm $MenuW
    echo -e "${YEL}NOTICE${NC} - when pasting your secret key here, it will be hidden on the terminal screen."
    local prompt="Please enter the secret key: "
    stty -echo # turn off echo strict
    while IFS= read -rp "$prompt" -srn 1 char; do
        [[ "$char" == $'\0' ]] && { break; } # check for term/ENTER keypress
        if [[ "$char" == $'\177' ]] ; then # check for backspace
            if (( chars > 0 )); then
                chars=$((chars-1)) # backup char count by 1
                prompt=$'\b \b' # backup display prompt
                input="${input%?}" # delete last char from input
            else { prompt=''; } # remove prompt if no chars were found
            fi
        else
            chars=$((chars+1)) # increment chars
            prompt='*' # replace prompt with mask
            input+="$char" # add actual char to input
        fi
    done
    sleep .5s # slow down just in case input buffer is overflowed, which could cause input to appear on stdout
    stty echo; echo # turn echo back on then feed a line to make sure the cursor moves off the input line
    if [[ -n "$input" ]]; then
        encrypt_sk "$input" > "$CredentialPath" && chmod 640 "$CredentialPath" && unset input
    else
        echo -e "${RED}ERROR${NC} - Invalid or empty secret key of length:[${#input}] was entered."
        return 1
    fi
    echo; echo
}

########################### JSON PARSING CHECK #############################
function check_for_jq () {
    [[ -z $(which jq 2>/dev/null) ]] && { UseNativeJsonParser=true;  
        local jmsg="${YEL}WARNING${NC} - JSON utility \"JQ\" was not found, so we will be using Bash's \"native\" binaries with regex to parse JSON, serialize logs, \
read log metadata, get token expiration date and set vars. It is strongly recommended that you do not set the PageSize higher than 500 when \
not using JQ. The collector gathers logs into an array and reverses the order of output so that the logs print to file from old to new, top \
to bottom. This process runs signficantly slower using native GNU binaries: grep, sed, and tac. To install JQ simply run: 'sudo apt|dnf|yum install jq'.";
        fold -w $MenuW -s <<< "$jmsg"; echo
    }
}
########################## CONFIG FILE MANAGEMENT FUNCTIONS ##########################
function update_config_file () {
    local config_param="${1^^}"
    local config_value="${2//\"/}"
    local config_file="$3" 
    if [[ -z "$config_file" ]] || [[ ! -f "$config_file" ]]; then
        config_file="$ConfigPath"
        echo -e "${CYA}INFO${NC} - [get_oldactid_from_config] No configuration file was specified, using the default:[$config_file]." >&2
    fi
    if [[ -z "$config_param" ]]; then
        echo -e "${RED}ERROR${NC} - [update_config_file] No configuration parameter was specified to update." >&2
        return 1
    else
        local config_match=$(grep -Pio "${config_param}" "$config_file")
        local new_line="${config_param^^}=${config_value}"
        if [[ -z "$config_match" ]]; then
            echo "$new_line" >> "$config_file" && echo -e "${GRE}OKAY${NC} - [update_config_file] Configuration parameter:[$config_param] was added to configuration file successfully."
            return 0
        else
            sed -i "s/${config_match}=.*/${new_line}/" "$config_file" 2>/dev/null && echo -e "${GRE}OKAY${NC} - [update_config_file] Configuration parameter:[$config_param] was updated in configuration file with value:[$config_value] successfully."
            return 0
        fi    
    fi  
}
function setup_systemd_service_file () {
    if [[ -f "$ServiceFile" ]] && (( $(wc -l < "$ServiceFile" 2>/dev/null) > 1 )); then
        echo -e "${YEL}WARNING${NC} - systemd service file already exists at:[$ServiceFile] and is not empty."
        read -rp "Do you want to overwrite it? (y/n): " choice
        if [[ "${choice,,}" == 'y' || "${choice,,}" == 'yes' ]]; then
            rm -f "$ServiceFile" && { setup_systemd_service_file; }
        else
            echo -e "${CYA}INFO${NC} - Existing systemd service file will not be modified."
        fi
    elif [[ ! -f "$ServiceFile" ]]; then
        echo " " | tee "$ServiceFile" # create empty file if it doesn't exist
        echo -e "
        [Unit]
        Description=Fortra's NinjaOne Activity Log Collector
        After=network.target
        User=root
        Group=root

        [Service]
        ExecStart=/usr/bin/$AppName.sh

        [Install]
        WantedBy=multi-user.target" >> "$ServiceFile" && chmod +x "$ServiceFile"
    fi 
}
function setup_systemd_timer_file () {
    if [[ -f "$TimerFile" ]] && (( $(wc -l < "$TimerFile" 2>/dev/null) > 1 )); then
        echo -e "${YEL}WARNING${NC} - systemd timer file already exists at:[$TimerFile] and is not empty."
        read -rp "Do you want to overwrite it? (y/n): " choice
        if [[ "${choice,,}" == 'y' || "${choice,,}" == 'yes' ]]; then
            rm -f "$TimerFile" && { setup_systemd_timer_file; }
        else
            echo -e "${CYA}INFO${NC} - Existing systemd timer file will not be modified."
        fi
    else
        echo " " | tee "$TimerFile" # create empty file if it doesn't exist
        echo -e "
        [Unit]
        Description=Run Fortra's NinjaOne Activity Log Collector every $RunInterval minutes and on boot.

        [Timer]
        OnBootSec=${RunOnBootTime}min
        OnUnitActiveSec=${RunInterval}m

        [Install]
        WantedBy=timers.target" >> "$TimerFile" && chmod +x "$TimerFile"
    fi
}
function setup_log_rotation_file () {
    if [[ -f "$RotationFile" ]]; then
        echo -e "${YEL}WARNING${NC} - logrotate file already exists at:[$RotationFile]."
        read -rp "Do you want to overwrite it? (y/n): " choice
        if [[ "${choice,,}" == 'y' || "${choice,,}" == 'yes' ]]; then
            rm -f "$RotationFile" && { setup_log_rotation_file; }
        else
            echo -e "${RED}ERROR${NC} - logrotate file already exists at:[$RotationFile] and will not be modified."
        fi   
    else
        # log rotation settings can be modified here before install or at the config file location: /etc/logrotate.d/ninjaone_collector
        echo " " | tee "$RotationFile" # create empty file if it doesn't exist
        echo -e "$TargetLogPath/*.log {
            $RotationInterval
            rotate $RotateTimer
            compress
            maxage $MaxAge
            createtruncate
            missingok
            notifempty
        }" >> $RotationFile
    fi
}
function uninstall_collector () {
    local confirmed="${1:-no}"
    local do_rollback="${2:-no}"
    if [[ "$do_rollback" == 'rollback' ]]; then
        confirmed='yes'
    else
        echo "You have chosen to uninstall ${AppName^^} and remove all associated files including configuration, state and credential files."
        echo -e "${YEL}NOTE${NC} Uninstalling the collector will NOT delete any log files in the target directory:[$TargetLogPath]. Those must be deleted manually if desired."
    fi
    if [[ "$confirmed" == 'yes' ]]; then
        local -a files_to_remove=("$ServiceFile" "$TimerFile" "$RotationFile" "$ConfigPath" "$StateFile" "$CredentialPath" "/usr/bin/$AppFile" )
        echo -e "Rolling back application.\n${CYA}INFO${NC} - Removing $AppName services\nPlease wait..."
        sleep 2s
        systemctl stop $AppName.service 2>/dev/null && echo -e "${GRE}OKAY${NC} - Stopped $AppName service."
        systemctl disable $AppName.service 2>/dev/null && echo -e "${GRE}OKAY${NC} - Disabled $AppName service."
        systemctl stop $AppName.timer 2>/dev/null && echo -e "${GRE}OKAY${NC} - Stopped $AppName timer."
        systemctl disable $AppName.timer 2>/dev/null && echo -e "${GRE}OKAY${NC} - Disabled $AppName timer."
        sudo chattr -i "/usr/bin/$AppFile"
        for file in "${files_to_remove[@]}"; do
            [[ -f "$file" ]] && { rm -f "$file" && echo -e "${GRE}OKAY${NC} - Removed application file:[$file]."; }
        done
        rmdir -p "$SysConfSDir" 2>/dev/null && echo -e "${GRE}OKAY${NC} - Removed credential files and directory:[$SysConfSDir]."
        rmdir -p "$ConfigDir" 2>/dev/null && echo -e "${GRE}OKAY${NC} - Emptied and removed configuration directory:[$ConfigDir]."
        rmdir -p "$SysConfDir" 2>/dev/null && echo -e "${GRE}OKAY${NC} - Emptied and removed application library directory:[$SysConfDir]."
        #rm -f "/usr/bin/$AppFile" 2>/dev/null && echo -e "${GRE}OKAY${NC} - Removed application executable: []."
        systemctl daemon-reload && echo -e "${GRE}OKAY${NC} - Reloaded systemd daemon."
        echo -e "${GRE}OKAY${NC} - $AppName has been uninstalled. Service, timer, rotation, config, state and credential files have been removed."
        exit 0
    else
        echo -e "${RED}ERROR${NC} - Uninstallation aborted. Confirmation was denied by user. To try again, run the script with the '--uninstall' option and confirm with 'y|Y."
        exit 1
    fi
    echo; echo
}
function configure_system_files () {
    # Setup directories and files if they don't exist  
    [[ ! -d "$ConfigDir" ]] && { mkdir -p "$ConfigDir" && chmod 755 "$ConfigDir"; } && echo -e "${GRE}OKAY${NC} - Configuration directory was created at:[$ConfigDir]."
    [[ ! -f "$ConfigPath" ]] && { echo " " | tee "$ConfigPath" && chmod 644 "$ConfigPath"; } && echo -e "${GRE}OKAY${NC} - Configuration file was created at:[$ConfigPath]."
    { [[ ! -d "$SysConfDir" ]] && mkdir -p "$SysConfDir" && chmod 755 "$SysConfDir"; } && echo -e "${GRE}OKAY${NC} - Application library directory was created at:[$SysConfDir]."
    { [[ ! -d "$SysConfSDir" ]] && mkdir -p "$SysConfSDir" && chmod 711 "$SysConfSDir"; } && echo -e "${GRE}OKAY${NC} - SSL credential directory was created at:[$SysConfSDir]."
    { [[ ! -d "$TargetLogPath" ]] && mkdir -p "$TargetLogPath" && chmod 755 "$TargetLogPath"; } && echo -e "${GRE}OKAY${NC} - Target log directory was created at:[$TargetLogPath]."
    { [[ ! -f "$StateFile" ]] && echo " " | tee "$StateFile" && chmod 644 "$StateFile"; } && echo -e "${GRE}OKAY${NC} - State file was created at:[$StateFile]."
}
function get_class_filters () {
    echo; echo
    segm $MenuW
    echo -e "${YEL}GET CLASS FILTERS${NC}"
    segm $MenuW
    echo -e "${YEL}NOTE${CYA} To skip entering anything and just go with the defaults (all logs), press \"S\" or type \"SKIP\" and then Enter.${NC}"
    echo "You may optionally enter class filters to only get logs of certain classes, i.e.: SYSTEM, DEVICE, USER, ALL. (ALL is the default)"
    echo "You can copy and paste multiple lines at a time. When you are done, type 'QUIT' or 'Q' on a new line and press ENTER."
    while true; do
        read -rp "> " class
        if [[ "${class,,}" == 's' ]] || [[ "${class,,}" == 'skip' ]]; then
            echo "Skipping..." && break
        elif [[ "${class^^}" == "QUIT" ]] || [[ "${class^^}" == "Q" ]]; then
            break
        elif [[ "${class^^}" == 'ALL' ]]; then
            unset ClassFilters # use default
            break
        elif [[ -n $(echo "${ActivityClassFilters[@]}" | fgrep -wio "$class") ]]; then
            ClassFilters+=( "$class" )
        else
            echo -e "${YEL}WARNING${NC} Invalid class filter was entered:[${YEL}$class${NC}]. Please try again."
        fi
    done
    (( ${#ClassFilters[@]} >= 1 )) && echo -e "Got [${YEL}${#ClassFilters[@]}${NC}] filters from user."
}
function get_activity_filters () {
    echo; echo
    segm $MenuW
    echo -e "${YEL}GET ACTIVITY FILTERS${NC}"
    segm $MenuW
    echo -e "${YEL}NOTE${CYA} To skip entering anything and just go with the defaults (all logs), press \"sS\" or type \"SKIP\" and then Enter.${NC}"
    echo "You may optionally enter activity filters to only get logs of certain actvities."
    read -rp "Would you like to see a list of available activity filters? Enter yY|nN|sS to skip > " quest
    if  [[ "${quest,,}" == 's' ]] || [[ "${quest,,}" == 'skip' ]]; then { echo "Skipping..." && return 0; }
    elif [[ "${quest,,}" == 'y' ]] || [[ "${quest,,}" == 'yes' ]]; then { printf '%s\n' "${ActivityTypeFilters[@]}"; } 
    fi
    echo "You can copy and paste multiple lines at a time. When you are done, type 'QUIT' or 'Q' on a new line and press ENTER."
    while true; do
        read -rp "> " act
        if [[ "${act^^}" == "QUIT" ]] || [[ "${act^^}" == "Q" ]]; then
            break
        elif [[ -n $(echo "${ActivityTypeFilters[@]}" | fgrep -wio "$act") ]]; then
            TypeFilters+=( "$act" )
        else
            echo -e "${YEL}WARNING${NC} Invalid class filter was entered:[${YEL}$act${NC}]. Please try again."
        fi
    done
    (( ${#TypeFilters[@]} >= 1 )) && echo -e "Got [${YEL}${#TypeFilters[@]}${NC}] filters from user."
}
# STATUS CODES ARE NUMEROUS AND MESSY, IF THE USER WANTS TO FILTER BY THESE, LET THEM GIVE US A FILE
function get_status_filter_file () {
    echo; echo
    segm $MenuW
    echo -e "${YEL}GET STATUS FILTERS${NC}"
    segm $MenuW
    echo -e "${YEL}NOTE${CYA} To skip entering anything and just go with the defaults (all logs), press \"sS\" or type \"skip\" and then Enter.${NC}"
    echo "You may enter a file that contains status filters here. However, since there are 673 status filters as of this writing, you can only choose around 100 of them at a time."
    echo -e "To make this easier, you may submit an input file with the filters you dont want commented out with a \"#\" and these lines will be ignored." 
    echo -e "You may find the full status list file at $(pwd)/ninjaone_activity_status_codes.txt"
    while true; do
        read -rp "> " sfile
        if [[ "${sfile,,}" == 's' ]] || [[ "${sfile,,}" == 'skip' ]]; then
            echo "Skipping..." && break
        elif [[ "${sfile^^}" == "QUIT" ]] || [[ "${sfile^^}" == "Q" ]]; then
            break
        elif [[ -f "$sfile" ]]; then
            FilterFile="$sfile"
            break
        else
            echo -e "${YEL}WARNING${NC} File entered:[${YEL}$sfile${NC}] was missing or not found. Please try again."
        fi
    done
}
function set_configuration () {
    # Set configuration options based on parsed args and build our config file
    if ! $Uninstall; then
        # Set config options
        local InstallDate=$(date +%s)
        StartDateTime=$(date -d "$DateTime" +%s)
        local -A User_Config_Params=( [API_ENDPOINT]="$ApiEndpoint"
            [TARGET_LOG_PATH]="$TargetLogPath" [FIRST_RUN]="$FirstRun" [START_DELAY]="$StartDelay" [MAX_LOG_FILE_PERCENTAGE]="$MaxLogFilePercentage" 
            [MAX_RETRIES]="$MaxRetries" [RETRY_DELAY]="$RetryDelay" [FILTER_FILE]="$FilterFile" [LOG_FORMAT]="$TargetLogFormat" [START_AT_ACTID]="$StartAtId"
            [PAGE_SIZE]="$PageSize" [USE_NATIVE_JSON_PARSER]="$UseNativeJsonParser" [GET_ALL_AVAIL]="$GetAllAvailableLogs"
            [CLIENT_ID]="$ClientId" [SIGKEY]="$SigKey" [START_NOW]="$StartNow" [START_DATE_TIME]="$StartDateTime"
            [CREDENTIAL_PATH]="$CredentialPath" ) #[PRIV_KEY_FILE]="$PrivKeyPath" [PADLOCK_PATH]="$PadlockPath"
        local -A Advanced_Config_Params=( [RUN_ON_BOOT_TIME]="$RunOnBootTime" [MAX_AGE]="$MaxAge" [ROTATE_TIMER]="$RotateTimer" [ROTATION_INTERVAL]="$RotationInterval" [CONFIG_PATH]="$ConfigPath"
            [RUN_INTERVAL]="$RunInterval" [APP_FILE]="$AppFile" [STATE_FILE]="$StateFile" [SERVICE_FILE]="$ServiceFile" [TIMER_FILE]="$TimerFile" [INSTALL_DATE]="$InstallDate" )
        # Lets build our user config file with the given settings
        # Build the filter configs
        if (( ${#ClassFilters[@]} >= 1 )); then
            local clist=$(IFS=,; echo "${ClassFilters[*]}")
            update_config_file CLASS_FILTERS "$clist" "$ConfigPath"
        fi
        if (( ${#TypeFilters[@]} >= 1 )); then
            local tlist=$(IFS=,; echo "${TypeFilters[*]}")
            update_config_file TYPE_FILTERS "$tlist" "$ConfigPath"
        fi
        for param in "${!User_Config_Params[@]}"; do
            update_config_file "$param" "${User_Config_Params[$param]}" "$ConfigPath"
        done
        # Lets add advanced config params to the config file next with a warning first
        echo -e "\n\n# Advanced configuration parameters. These settings are only for backup in case of system failure. Changing these values will have no effect on operation of the script. If you want to modify the runtime variables, run the installation script again with flags and values set." >> "$ConfigPath"
        for param in "${!Advanced_Config_Params[@]}"; do
            update_config_file "$param" "${Advanced_Config_Params[$param]}" "$ConfigPath"
        done
    fi
}
function install_collector () {
    if (( $EUID != 0 )); then # check for sudo/root privs
        echo -e "${RED}ERROR${NC} - Please run install script with sudo privileges.\nIf you cannot use sudo privs, setup this app as a cron job instead of as a systemd service."
        exit 1
    else
        # prep executable and move it to /usr/bin
        if [[ ! -f "/usr/bin/$AppFile" ]]; then
            chmod +x "$AppFile" && cp "${AppFile}" /usr/bin && chattr +i /usr/bin/$AppFile && { 
                    echo -e "${GRE}OKAY${NC} - Application executable was installed at: [/usr/bin/$AppFile]."
                }
        elif [[ -f "/usr/bin/$AppFile" ]]; then
            echo -e "${YEL}WARNING${NC} - executable file already exists at:[/usr/bin/$AppFile]. Checking version date..."
            if [[ $(grep -Pio '(?<=Script_Version=\")\d+.\d+.\d+_[0-9]*(?=\")' ./ninjaone_collector.sh | cut -d_ -f2) -gt $(grep -Pio '(?<=Script_Version=\")\d+.\d+.\d+_[0-9]*(?=\")' /usr/bin/$AppFile | cut -d_ -f2) ]]; then
                echo -e "${CYA}INFO${NC} - Newer version of application file found. Updating executable at:[/usr/bin/$AppFile]."
                chmod +x "$AppFile" && cp "${AppFile}" /usr/bin && echo -e "${GRE}OKAY${NC} - Application executable was installed at: [/usr/bin/$AppFile]." 
            else
                echo -e "${RED}ERROR${NC} - Target application file:[$AppFile] is newer than the source. To force an update, please delete the target application file and run the installer again."
                echo "Rolling back installation..."
                uninstall_collector 'yes' 'rollback'
            fi
        fi      
        # setup directories and files if they don't exist
        echo -e "${CYA}INFO${NC} - Setting up configuration, state and log directories and files. Please wait..."; sleep 2s
        setup_systemd_service_file && echo -e "${GRE}OKAY${NC} - Systemd service file setup completed."
        setup_systemd_timer_file && echo -e "${GRE}OKAY${NC} - Systemd timer file setup completed."
        # setup log rotation
        echo -e "${CYA}INFO${NC} - Setting up log rotation file. Please wait..."; sleep 2s
        setup_log_rotation_file && echo -e "${GRE}OKAY${NC} - Log rotation file setup completed."
        # check if system files were created. If so, reload daemon, and then start service
        if [[ -f "$ServiceFile" ]] && [[ -f "$TimerFile" ]]; then
            echo -e "${GRE}OKAY${NC} - Systemd service and timer files were created successfully."
            echo -e "${GRE}OKAY${NC} - Reloading daemon and attempting to start service. Please wait..."; sleep 2s
            systemctl daemon-reload 
            systemctl enable --now $AppName.timer
            systemctl enable $AppName.service && systemctl start $AppName.service
            sleep 2s
            systemctl status $AppName.service --no-pager
            if [[ -n "$(systemctl list-timers --all | grep -io $AppName.timer)" ]]; then
                echo -e "${GRE}OKAY${NC} - Systemd service timer was installed and started successfully."
            else
                echo -e "${RED}ERROR${NC} - Failed to install systemd service timer at [${YEL}$TimerFile${NC}]. Check if you have rights to create system services on this machine."
                uninstall_collector 'yes' 'rollback'
            fi
        else
            echo -e "${RED}ERROR${NC} - installation failed; service file or timer service was not created."
            echo "Rolling back installation..."
            uninstall_collector 'yes' 'rollback'
        fi
    fi
}
function start () {
    # assign the full path to the credential file if it was specified as an option but we only got a file name
    if [[ "$CredentialFile" != '/*' ]] && [[ -n "$(readlink -e "$CredentialFile")" ]]; then
        CredentialPath="$(readlink -e $CredentialFile)"
    fi
    echo; echo
    segm $MenuW
    echo -e "This script will install the NinjaOne API log collector as a systemd service on this Linux system."
    segm $MenuW
    sleep 1s
    if $Uninstall; then
        read -rp "Are you sure you want to uninstall the ${AppName^^} collector and remove all files? (y/n): " uninst
        if [[ "${uninst,,}" == 'y' || "${uninst,,}" == 'yes' ]]; then
            uninstall_collector 'yes'
        fi
    else
        read -rp "Do you want to install the ${AppName^^} collector? (y|n): " choice
        if [[ ! "${choice,,}" == 'y' || "${choice,,}" == 'yes' ]]; then
            echo -e "Exiting installation script as requested. No changes were made."
            exit 0
        else
            #Uninstall=false
            echo
            echo -e "Starting installation processes. Please wait..."; sleep 1s
            echo -e "Checking for pre-requisites..."
            check_pre_requisites || uninstall_collector 'yes' 'rollback'
            echo -e "\nSetting up system files and directories. Please wait..."; sleep 1s
            check_for_jq
            configure_system_files 
            # Now prompt for Client ID and Client Secret if not set in env or credential file
            if [[ -n "$CredentialPath" && ! -f "$CredentialPath" ]] || (( $(wc -l < "$ConfigPath" 2>/dev/null) <= 2 )); then
                echo -e "${YEL}WARNING${NC} - No credential file was found at:[$CredentialPath]. Getting data from user..."; sleep 2s
                echo -e "${YEL}NOTE${NC} - You will be prompted to enter your NinjaOne API Client ID if not already set in the environment, a credential file, or from the command line." 
                echo -e "However, you will be prompted to enter the Client Secret here to store it encrypted even if you enter a ClientId as a command line argument."
                if [[ -z "$ClientId" ]]; then
                    echo -e "${YEL}WARNING${NC} - Client ID was not set on the command line. Getting data from user..."; sleep 2s
                    get_clientid_from_user
                fi
                echo " " | tee "$CredentialPath"
                get_clientsecret_from_user      
            fi
            # get optional filters
            get_class_filters
            get_activity_filters
            get_status_filter_file
            echo -e "Setting configuration options and building config file."; sleep 2s
            set_configuration
            # Finally, if the encrypted filepath exists then install the collector as a systemd service
            if [[ -f "$CredentialPath" ]]; then 
                echo -e "${GRE}OKAY${NC} - All configuration settings have been set. Now installing the collector as a systemd service."
                sleep 2s
                install_collector
            else
                echo -e "${RED}ERROR${NC} - Client ID or Client Secret was not set. Cannot continue installation without these values."
                uninstall_collector 'yes' 'rollback'
            fi
        fi
    fi
}
declare -i postat opterr
declare parsed_opts
[[ $# -eq 0 ]] && { echo -e "${YEL}WARNING${NC} - No input parameters [$#] were found on stdin. Running with default settings."; }
getopt -T > /dev/null; opterr=$?  # check for enhanced getopt version
if (( $opterr == 4 )); then  # we got enhanced getopt
    declare Long_Opts=url-endpoint:,client-id:,run-interval:,run-onboot-time:,max-log-age:,log-rotation-interval:,log-rotate-timer:,config-file:,start-at-actid:,start-at-datetime:,page-size:,target-directory:,target-format:,filter-file:,credential-file:,start-now,get-all-logs,uninstall,force-first-run,debug,help 
    declare Opts=u:k:i:b:g:y:z:c:s:p:t:l:f:a:m:nrjxdh
    ! parsed_opts=$(getopt --longoptions "$Long_Opts" --options "$Opts" -- "$@") # load and parse options using enhanced getopt
    postat=${PIPESTATUS[0]}
else 
    ! parsed_opts=$(getopt u:k:i:b:g:y:z:c:s:p:t:l:f:a:m:nrjxdh "$@") # load and parse avail options using original getopt
    postat=${PIPESTATUS[0]}
fi
if (( $postat != 0 )) || (( $opterr != 4 && $opterr != 0 )); then # check return and pipestatus for errors
    echo -e "${RED}ERROR${NC} - invalid option was entered:[$*] or missing required arg."
    install_collector_usage
    exit 1 
else 
    eval set -- "$parsed_opts"  # convert positional params to parsed options ('--' tells shell to ignore args for 'set')
    while true; do 
        case "${1,,}" in
            -u|--url-endpoint )     { { [[ -n $(grep -Pio $_URL_REGEX <<< "${2//\"/}") ]] && ApiEndpoint="${2//\"/}"; }; shift 2; } ;;
            -k|--client-id )        { { [[ -n "${2//\"/}" ]] && ClientId="${2//\"/}"; }; shift 2; } ;;
            -i|--run-interval )     { { [[ "${2//\"/}" =~ $_NUM_REGEX ]] && RunInterval="${2//\"/}"; }; shift 2; } ;;
            -b|--run-onboot-time )  { { [[ "${2//\"/}" =~ $_NUM_REGEX ]] && RunOnBootTime="${2//\"/}"; }; shift 2; } ;;
            -g|--max-log-age )      { { [[ "${2//\"/}" =~ $_NUM_REGEX ]] && MaxAge="${2//\"/}"; }; shift 2; } ;;
            -y|--log-rotation-interval ) { { [[ "${2//\"/}" =~ ^(daily|weekly|monthly)$ ]] && RotationInterval="${2//\"/}"; }; shift 2; } ;;
            -z|--log-rotate-timer ) { { [[ "${2//\"/}" =~ $_NUM_REGEX ]] && RotateTimer="${2//\"/}"; }; shift 2; } ;;
            -c|--config-file )      { { [[ -f "${2//\"/}" && "${2//\"/}" =~ $_FILENAME_REGEX ]] && ConfigPath="${2//\"/}"; }; shift 2; } ;;
            -s|--start-at-actid )   { { [[ "${2//\"/}" =~ $_NUM_REGEX ]] && StartAtId="${2//\"/}"; }; shift 2; } ;;
            -p|--page-size )        { if [[ "${2//\"/}" =~ $_NUM_REGEX ]] && (( $2 > 0 && $2 <= MaxPageSize )); then { PageSize="${2//\"/}"; } fi; shift 2; } ;;
            -t|--target-directory ) { { [[ -d "${2//\"/}" ]] && TargetLogPath="${2//\"/}"; }; shift 2; } ;;
            -l|--target-format )    { { [[ "${2//\"/}" =~ $_DATE_FORMAT_REGEX ]] && TargetLogFormat="${2//\"/}"; }; shift 2; } ;;
            -f|--filter-file )      { { [[ -f "${2//\"/}" ]] && FilterFile="${2//\"/}"; }; shift 2; } ;;
            -a|--credential-file )  { { [[ -f "${2//\"/}" ]] && CredentialFile="${2//\"/}"; }; shift 2; } ;;
            -m|--start-at-datetime ) { { [[ -n "${2//\"/}" ]] && DateTime="${2//\"/}"; }; shift 2; } ;;
            -n|--start-now )        { StartNow=true; shift; } ;;
            -r|--force-first-run )  { FirstRun=true; shift; } ;;
            -j|--get-all-logs )     { GetAllAvailableLogs=true; shift; } ;;
            -x|--uninstall )        { Uninstall=true; echo -e "${CYA}INFO${NC} - Uninstalling $AppName..."; shift; } ;;
            -d|--debug )            { set -x; shift; } ;;
            -h|--help )             { install_collector_usage; shift && exit 0; } ;;
            -- ) shift; break ;;  # end of options            
        esac
    done
fi
start
