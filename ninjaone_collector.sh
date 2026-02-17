#!/usr/bin/env bash
# shellcheck disable=SC2155,SC2119,SC2004,SC2053,SC2027,SC2086,SC2120,SC2091,SC2001,SC2184
# Aaron Celestin aaron.celestin@fortra.com
# DATE AND TIME VERSION of previous script
set -o pipefail
# This script collects NinjaOne logs from API and saves them a specified directory to send to a SIEM.
declare -r Script_Version="0.3.21_20260217"
# It requires the following environment variables to be set:
# Client ID, Client Secret, API Endpoint, and Target Log Directory.
declare -r AppName='ninjaone_collector'
declare AuthToken=""
declare -i AuthExpiry=0
declare _UUID_REGEX='^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$'
declare _NUM_REGEX='^[0-9]+$'
declare _URL_REGEX='^(https://[^\s/$.?#].[^\s]*$'
declare _FILENAME_REGEX='[a-zA-Z0-9_\-. ]+'
declare _DATE_FORMAT_REGEX='^(YYYYMMDD|YYYY-MM-DD|MMDDYYYY|MM-DD-YYYY|DDMMYYYY|DD-MM-YYYY|YYMMDD|YY-MM-DD|DDMMYY|DD-MM-YY|MMDDYY|MM-DD-YY)$' # ^[YMD\-._]+
declare ConfigDir="/etc/${AppName,,}"
declare ConfigPath="$ConfigDir/app.conf"
declare SysConfDir="/var/lib/$AppName"
declare CredentialFile=".apiinfo" # default credential file name
declare SysConfSDir="$SysConfDir/.ssl"
declare CredentialPath="$SysConfSDir/$CredentialFile" # default full path to credential file
declare StateFile="$ConfigDir/.lastrun.state"
declare DefaultCredFile="$SysConfSDir/.apiinfo"
declare DefaultEndpoint='https://us2.ninjarmm.com/v2/activities'
declare -ir MaxPageSize=1000
declare DefaultLogFormat='YYYYMMDD'
declare -i StartAtActId
declare ClassFilters=
declare TypeFilters= 
declare StatusFilters
#declare -i ThisNow=$(date +%s) # get the datetime of this instance's runtime
declare ApiEndpoint 
declare DefaultLogPath="/var/log/${AppName}"
function san () { tr -dc '[:alnum:][=/=][=.=][=-=][=_=][=:=][=+=]' <<< "$*" ; }
function segm () { local -i w=$1; for ((i=0;i<$w;i++)); do echo -en '-'; done; echo; }
function collector_usage () {
    local eline='+============================================================================+'
    local scrw=$(tput cols 2>/dev/null || echo 150)
    local title="Ninja One API Log Collector"
    local vtitle="Version: ${Script_Version}"
    echo -e "$eline"
    printf '%-18s %32s %26s\n' "|" "$title" "|" 
    printf '%-15s %32s %29s\n' "|" "$vtitle" "|"
    echo -e "$eline"; 
    local -i exit_code=${1:-0}
    local -i scrw=$(( $(tput cols) -6 ))
    col1=$(( scrw * 2/80))
    col2=$(( scrw * 11/80))
    col3=$(( scrw * 67/80))
    #col4=$(( scrw * 56/80))  
    echo
    local desc="This script collects NinjaOne Activity logs from NinjaOne's API and saves to a specified directory so that they may ultimately be sent to Fortra's SIEM log aggregation and storage platform. It requires the following script variables to be set: Client ID, Client Secret, API Endpoint, and Target Log Directory. \
You may optionally specify a filter file that contains NinjaOne log filters by CLASS, TYPE and RESULT. See NinjaOne Activity Log API documentation for more informtion."
    echo -e "DESCRIPTION:"
    fold -w $scrw -s <<< "$desc"
    local nstate="The script will create a state file to track the last-stored log activity ID. This file is located at: '$StateFile'. Do not delete this file unless you want to re-collect all logs from the beginning. If you want to change the starting activity ID, you may edit this file state or use the '--start-at-actid' option when running it from the command line. \
Any options set when this script is run from the command line will not be stored in the config file. If you want to make permanent changes to the behavior of the script, either manually modify the config file or run the reinstaller again."
    echo -e "\nSTATE FILE:"
    fold -w $scrw -s <<< "$nstate"
    local ncreds="You may set the API auth variables: ClientId and ClientSecret in a credential file, although this is not recommended. Be sure to set the permissions of the creds file to 0600 before running the script. Then call the collector script with the '--credential-file' option pointing to the path to your credential file."
    echo -e "\nAPI CREDENTIALS:"
    fold -w $scrw -s <<< "$ncreds"
    echo -e "\nEXAMPLES:"
    local bn=$(basename "$0")
    local -a examples=(
        "$bn --start-at-actid '1234567890' --page-size '500' --target-format 'DD-MM-YY' --filter-file '\$HOME/filters.txt'"
        "$0 --url-endpoint 'https://us2.ninjarmm.com/v2/activities' --client-id 'xyz12345689abcdefg987645321'"
        "$bn --config-file '/path/to/custom_config.conf' --force-first-run --target-directory '/var/logs/ninjaone'"
        "$0 --credential-file '/path/to/credsfile' --config-file './custom_config.conf' --force-first-run"
        "$bn --help"
    )
    for example in "${examples[@]}"; do
        echo -e "bash \$ $example" | fold -w $scrw -s
    done
    local note5="NOTE: Most special characters entered for filenames or paths will be ignored or removed IMMEDIATELY to avoid issues with script operation. Only alphanumeric characters and the following characters are allowed:[ / . - _ : + ]"
    echo; echo -e "$note5" | fold -w $scrw
    echo -e "\nOPTIONS:" 
    local -a options=(
    "-u,--url-endpoint,Specify the NinjaOne API endpoint URL. Default is '$ApiEndpoint'."
    "-k,--client-id,Specify your NinjaOne API Client ID. You will be prompted to enter this if not set in the environment or credential file."
    "-a,--start-at-actid,Specify the start activity ID to begin collection at. Default start activity ID is 1 on the FirstRun."
    "-p,--page-size,Specify the number of logs to retrieve per API call. Default is 200. Max is 1000."
    "-t,--target-directory,Specify the directory to save collected logs. Default is '$TargetLogPath'."
    "-l,--target-format,Specify the log file date format. Default is 'YYYYMMDD'."
    "-f,--filter-file,Specify the path to a filter file containing a list of custom filters."
    "-c,--credential-file,Specify the path to your credential file. Default is '$CredentialPath'."
    "-r,--force-first-run,Force the collector to run in FirstRun mode, backing up existing user config if it exists."
    "-d,--debug,Enable debug mode for verbose output."
    "-h,--help,Display this help message and exit." )
    if (( $(tput cols) < 80 )); then
        echo -e "ERROR: Terminal width is too narrow to display the help menu. Please increase the width of the terminal."
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
function get_all_actids () {
    local json="$*"
    local -a idlist
    if $UseNativeJsonParser; then # if jq is not available, use an ugly regex to parse json, note the look-ahead and look-behind to get only the activities array
        if (( ${#json} <= 50 )); then
            idlist[0]='null'
        else
            readarray -t idlist <<< "$(grep -Pio '(?<={"id":)[0-9]+(?=,")' <<< "$json")"
        fi
    else
        readarray -t idlist <<< "$(jq -r '.activities[].id' <<< "$json")"
    fi
    echo "${idlist[@]}"
}
function get_lastactivity_id () {
    local json="$*"
    if $UseNativeJsonParser; then
        grep -Pio '(?<="lastActivityId":)[0-9]+(?=,")' <<< "$json" 
    else
        jq -r '.activities[0].id' <<< "$json"
    fi
}
# try to decrypt incoming string using Sigkey
function decrypt_sk () {
    local sigkey="${1?'ERROR - [decrypt_sk] No signature key was specified to decrypt the secret.'}"
    shift 
    local in="$*"
    echo "$in" | openssl enc -aes-256-cbc -a -d -salt -pbkdf2 -pass pass:$sigkey
}
function decrypt_and_read_file () {
    local private_key="${1:-$PrivateKeyFile}"
    local infile="${2:-$CredentialPath}"
    local outfile="${3:-${infile}.dec}"
    if [[ ! -f "$infile" ]] || [[ ! -f "$private_key" ]]; then
        echo "ERROR - [decrypt_file] Invalid or missing private key or input file:[$infile] or [$private_key] was missing or inaccessible." >&2
        return 1
    else
        openssl pkeyutl -decrypt -inkey "$private_key" -in "$infile" -out "$outfile" && cat "$outfile" && rm -f "$outfile" 2>/dev/null
    fi
}  
function get_auth_token () {
    local auth_url='https://us2.ninjarmm.com/ws/oauth/token'
    local auth_data="client_id=${ClientId}&client_secret=$(decrypt_sk "$SigKey" $(sudo cat "$CredentialPath"))&grant_type=client_credentials&scope=monitoring"
    local auth_response=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "${auth_data}" "${auth_url}")
    local -i status_code=${PIPESTATUS[0]}
    if (( status_code != 0 )); then
        echo "ERROR - [get_auth_token] Failed to get authentication token. Error data:[$auth_response]." >&2
        return 1
    else
        local -i now=$(date +%s)
        if $UseNativeJsonParser; then
            AuthToken=$(cut -d, -f1 <<< "$(sed "s/[{}]//g" <<< "$auth_response")" | cut -d: -f2 | tr -d '"')
            AuthExpiry=$(( now + $(cut -d, -f2 <<< "$(sed "s/[{}]//g" <<< "$auth_response")" | cut -d: -f2 | tr -d '"') ))
        else
            AuthToken=$(jq -r '.access_token' <<< "${auth_response}")
            AuthExpiry=$(( now + $(jq -r '.expires_in' <<< "${auth_response}") ))
        fi
        echo "INFO - [get_auth_token] Successfully retrieved authentication token. Expires:[$(date -d @$AuthExpiry)]."
        return 0
    fi
}
function check_token_expiration () {
    if [[ -n "$AuthExpiry" ]] && (( $(date +%s) >= $AuthExpiry )); then
        echo true
    else { echo false; }
    fi
}
function make_filters () {
    local filter_type="$1"
    IFS=, read -ra values <<< "$2"
    if (( ${#values[@]} == 0 )); then # if no filters specified, return empty string
        return 0
    else
        local output sep='&'
        for val in "${values[@]}"; do
            output+="${sep}${filter_type}=${val//\"/}"
        done
        echo "$output"
    fi
}
function make_status_filters_from_file () {
    local filter_file="$1"
    local output
    if [[ -z "$filter_file" ]] || [[ ! -f "$filter_file" ]]; then
        echo "WARNING - [make_status_filters_from_file] Invalid or missing filter file:[$filter_file]. No filters will be applied" >&2
        return 0
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]] || [[ "$line" =~ ^#.*$ ]]; then
            continue # skip empty lines
        else
            output+="&status=${line//\"/}"
        fi
    done < "$filter_file"
    echo "$output"
}
function build_filter_string () {
    local class_filts type_filts sep='&'
    if [[ -n "$ClassFilters" ]]; then { class_filts=$(make_filters class "$ClassFilters"); } fi
    if [[ -n "$TypeFilters" ]]; then { type_filts=$(make_filters type "$TypeFilters"); } fi
    echo "${class_filts}${type_filts}"
}
# convert a json data stream to serialized log data in reverse order, since ninjaone logs come out backwards (newest-to-oldest)
function serialize_logs () {
    local json_data="${*:-$(</dev/stdin)}"
    if $UseNativeJsonParser; then # if jq is not available, use an ugly regex to parse json, note the look-ahead and look-behind to get only the activities array
        echo "$json_data" | grep -Po '(?<="activities":\[)(\{.*\}\}\})(?=\]\})' | sed 's/},{/}\n{/g' | tac
    else
        jq -rc '.activities | .[]' <<< "$json_data" | tac
    fi
}
function collect_logs () {
    local url="$1"
    local auth_token="$2"
    curl --request GET --url "$url" -H 'Accept: application/json' -H "Authorization: Bearer ${auth_token//\"/}" 
}
function log_disk_usage_exceeded () {
    local folder_path="$1"
    if [[ -z "$folder_path" ]] || [[ ! -d "$folder_path" ]]; then
        echo "WARNING - [get_folder_size] Specified folder path:[$folder_path] does not exist or is not a directory. Using default target log directory:[$TargetLogPath] instead." >&2
        folder_path="$TargetLogPath"
    fi
    local -i folder_size=$(du -sb "$folder_path" 2>/dev/null | cut -f1)
    local -i total_disk_size=$(df -B1 --output=size / | cut -d$'\n' -f2)
    if [[ -z "$folder_size" ]]; then
        echo "ERROR - [get_folder_size] Unable to determine size of target folder:[$folder_path]. Please ensure the directory exists and is accessible." >&2
        return 1
    fi
    if (( $(awk "BEGIN {printf \"%d\", ($folder_size / $total_disk_size) * 100}") >= $MaxLogFilePercentage )); then
        echo true
    else
        echo false
    fi
}
function get_lastrun_from_state () {
    local lastrun_actid
    if [[ -n "$StateFile" ]] && [[ -f "$StateFile" ]]; then
        local line=$(grep -Pi '^LASTRUN_ACTID' "$StateFile")
        lastrun_actid=$(cut -d'=' -f2 <<< "$line" 2>/dev/null) # get everything after the first = and trim leading/trailing spaces
        if [[ -z "$lastrun_actid" ]] || [[ ! "$lastrun_actid" =~ $_NUM_REGEX ]]; then
            echo "ERROR - [get_lastrun_from_state] Invalid or missing LASTRUN_ACTID in state file. The data we got was not a number." >&2
            exit 1
        else { echo "$lastrun_actid"; }
        fi
    else 
        echo "ERROR - [get_lastrun_from_state] Empty or missing StateFile." >&2
        exit 1
    fi
}
function write_lastrun_to_state () {
    local -i lastrun_actid="$1"
    if [[ -n "$StateFile" ]] && [[ -f "$StateFile" ]]; then
        echo "LASTRUN_ACTID=$lastrun_actid" > "$StateFile"
        echo "INFO - [write_lastrun_to_state] Successfully overwrote LASTRUN_ACTID:[$lastrun_actid] to state file:[$StateFile]."
        return 0
    elif [[ -n "$StateFile" ]] && [[ ! -f "$StateFile" ]]; then
        echo "LASTRUN_ACTID=$lastrun_actid" | tee "$StateFile"
        echo "INFO - [write_lastrun_to_state] Successfully created state file:[$StateFile] and wrote LASTRUN_ACTID:[$lastrun_actid] to it."
        return 0
    else
        echo "ERROR - [write_lastrun_to_state] Invalid or missing path to StateFile. Try running the installation script again." >&2
        exit 1
    fi
}
# Given a config param, value and optional config file, update or add the param in the file with the new value
function update_config_file () {
    local config_param="${1^^}"
    local config_value="$2"
    if [[ -z "$config_param" ]]; then
        echo "ERROR - [update_config_file] No configuration parameter was specified to update." >&2
        return 1
    else
        local config_match=$(grep -Pio "${config_param}" "$ConfigPath")
        local new_line="${config_param}=${config_value}"
        if [[ -z "$config_match" ]]; then
            echo "$new_line" >> "$ConfigPath" && echo "INFO - [update_config_file] Configuration parameter:[$config_param] was added to configuration file successfully."
            return 0
        else
            sed -i "s/${config_match}=.*/${new_line}/" "$ConfigPath" && echo "INFO - [update_config_file] Configuration parameter:[$config_param] was updated in configuration file successfully."
            return 0
        fi    
    fi  
}
# Given a config param and optional config file, return the value of the param from the file
function read_config_file () {
    local config_param="$1"
    if [[ -z "$config_param" ]]; then
        echo "ERROR - [read_config_file] No configuration parameter was specified to read." >&2
        return 1
    else
        local config_line=$(grep -Pi "^${config_param}" "$ConfigPath")
        local config_value=$(cut -d'=' -f2 <<< "$config_line" 2>/dev/null) # get everything after the first = and trim leading/trailing spaces
        if [[ -z "$config_value" ]]; then
            echo "WARNING - [read_config_file] Configuration parameter:[$config_param] not found or has no value in configuration file:[$ConfigPath]." >&2
            return 1
        else
            echo "$config_value"
        fi    
    fi  
}
function convert_format () {
    local format_string="${1:-$DefaultLogFormat}"
    local converted_format
    case ${format_string^^} in
        YYYYMMDD ) converted_format='%Y%m%d' ;;
        YYYY-MM-DD ) converted_format='%Y-%m-%d' ;;
        MMDDYYYY ) converted_format='%m%d%Y' ;;
        MM-DD-YYYY ) converted_format='%m-%d-%Y' ;;
        DDMMYYYY ) converted_format='%d%m%Y' ;;
        DD-MM-YYYY ) converted_format='%d-%m-%Y' ;;
        YYMMDD ) converted_format='%y%m%d' ;;
        YY-MM-DD ) converted_format='%y-%m-%d' ;;
        DDMMYY ) converted_format='%d%m%y' ;;
        DD-MM-YY ) converted_format='%d-%m-%y' ;;
        MMDDYY ) converted_format='%m%d%y' ;;
        MM-DD-YY ) converted_format='%m-%d-%y' ;;
        * ) echo "WARNING - [convert_format] Invalid log date format specified:[$format_string]. Using default format:[$DefaultLogFormat]." >&2; converted_format='%Y%m%d' ;;
    esac
    echo "$converted_format"
}
function get_configs_from_file () {
    local -a config_params=( 'API_ENDPOINT' 'TARGET_LOG_PATH' 'LOG_FORMAT' 'PAGE_SIZE' 'FIRST_RUN' 'START_DELAY' 'MAX_LOG_FILE_PERCENTAGE' 'MAX_RETRIES' 'RETRY_DELAY' 
        'START_AT_ACTID' 'USE_NATIVE_JSON_PARSER' 'CREDENTIAL_PATH' 'FILTER_FILE' 'CLIENT_ID' 'SIGKEY' 'START_NOW' 'START_DATE_TIME' 'GET_ALL_AVAIL' 'INSTALL_DATE' 
        'CLASS_FILTERS' 'TYPE_FILTERS' ) 
    for param in "${config_params[@]}"; do
        local value=$(read_config_file "$param")
        case ${param,,} in
            api_endpoint )          ApiEndpoint="${value:-$DefaultEndpoint}" ;;
            target_log_path )       TargetLogPath="${value:-$DefaultLogPath}" ;;
            log_format )            TargetLogFormat=$(convert_format "${value:-$DefaultLogFormat}") ;;
            page_size )             PageSize="${value:-200}" ;;
            first_run )             FirstRun="${value:-false}" ;;
            get_all_avail )         GetAllAvailableLogs="${value:-false}" ;;
            start_at_actid)         StartAtActId="${value}" ;;
            start_delay )           StartDelay="${value:-5}" ;;
            max_log_file_percentage ) MaxLogFilePercentage="${value:-70}" ;;
            max_retries )           MaxRetries="${value:-3}" ;;
            retry_delay )           RetryDelay="${value:-10}" ;;
            sigkey )                SigKey="${value}" ;; # no default signature key, must be set
            use_native_json_parser ) UseNativeJsonParser="${value:-true}" ;;
            credential_path )       CredentialPath="${value:-$DefaultCredFile}" ;;
            client_id )             ClientId="${value}" ;; # no default client ID, must be set
            filter_file )           FilterFile="${value}" ;; # default filter file is null/empty, meaning no filters
            start_now )             StartNow="${value:-true}" ;;
            start_date_time )       StartDateTime="${value}" ;;
            install_date )          InstallDate="$value" ;;
            class_filters )         ClassFilters="$value" ;; 
            type_filters )          TypeFilters="$value" ;;
            status_filters )        StatusFilters="$value" ;;
        esac 
    done 
}
function main () {
    local url json_logs
    local -a actids
    local -i StartId FinalId
    get_configs_from_file
    if [[ -f "$CredentialPath" && -n "$SigKey" ]]; then
        #local temp_credfile=$(mktemp /var/lib/${AppName}/.cred.XXXXXX)
        #decrypt_and_read_file "$PrivateKeyFile" "$CredentialPath"
        get_auth_token || { echo "ERROR - [main] Unable to get authentication token. Exiting." >&2; exit 1; }
        if ! check_token_expiration; then
            echo "ERROR - [main] Authentication token is expired or invalid. Exiting." >&2
            if (( RetryCount >= MaxRetries )); then
                echo "ERROR - [main] Maximum retry attempts reached whille attempting to refresh bearer token. Exiting." >&2
                exit 1
            fi
            echo "INFO - [main] Retrying to get authentication token in $RetryDelay seconds..." >&2
            sleep $RetryDelay   
            RetryCount=$(( RetryCount + 1 ))
            main
        fi
        RetryCount=0
    else { echo "ERROR - [main] Missing signature key or credential file. Exiting." >&2; exit 1;    }
    fi
    #sleep $StartDelay
    if [[ ! -d "$TargetLogPath" ]]; then # check if target log path exists, if not create it
        mkdir -p "$TargetLogPath"
    fi
    local exlog=$(log_disk_usage_exceeded "$TargetLogPath")
    if $exlog; then # check if we are exceeding max disk usage for the disk, die if we are
        echo "ERROR - [main] Disk usage for target log directory:[$TargetLogPath] has exceeded the maximum allowed percentage of $MaxLogFilePercentage% before first run. Exiting." >&2
        exit 1
    fi
    local filters=$(build_filter_string)
    # STATUS CODES ARE NUMEROUS MESSY, IF THE USER WANTS TO FILTER BY THESE, LET THEM GIVE US A FILE
    filters+=$(make_status_filters_from_file "$FilterFile")
    # Setup initial vars so we know where we are in the logs
    if $FirstRun; then
        if $StartNow; then # on first run, start at install datetime and get the latest log id
            url="${ApiEndpoint}?${filters}&after=${InstallDate}&pageSize=10" # this should bring back nothing but the latest log at most and the lastActivityId
            json_logs=$(collect_logs "$url" "$AuthToken")  # when using "NEWERTHAN" or "AFTER", you always get the absolute most recent logs, with now date should return no logs
            FinalId=$(get_lastactivity_id "$json_logs")
            StartId=$FinalId
        elif [[ "$StartDateTime" =~ $_NUM_REGEX ]] && ! $StartNow; then # on first run, convert start datetime to activity ID at that time
            url="${ApiEndpoint}?${filters}&before=${StartDateTime}&pageSize=10" # dont know where to start so this should bring oldest log before the startdatetime 
            json_logs=$(collect_logs "$url" "$AuthToken")
            FinalId=$(get_lastactivity_id "$json_logs")
            IFS=' ' read -ra actids <<< "$(get_all_actids "$json_logs")"
            if [[ "${actids[0]}" != 'null' ]]; then
                StartId="${actids[-1]}" # set the next log pull target to PageSize or value set at installation to start from, the beginning of all logs
            else
                StartId=$FinalId # we didnt get any logs, possibly filtered on the first run. nothing left to do but wait for the logs we want
            fi
        elif $GetAllAvailableLogs; then
            echo "WARNING - THIS WILL COLLECT ALL LOGS AVAILABLE FROM NINJAONE"
            url="${ApiEndpoint}?${filters}&after=$(date +%s)&pageSize=10" # we are starting at 1 anyway so no need to start getting logs yet
            json_logs=$(collect_logs "$url" "$AuthToken")  # when using "NEWERTHAN" or "AFTER", you always get the absolute most recent logs, with now date should return no logs
            FinalId=$(get_lastactivity_id "$json_logs")
            StartId=1
        elif [[ "$StartAtActId" =~ $_NUM_REGEX ]]; then
            url="${ApiEndpoint}?${filters}&after=$(date +%s)&pageSize=10" # we know where to start, no need to pull anything back yet; should bring back nothing but the latest log at most and the lastActivityId
            json_logs=$(collect_logs "$url" "$AuthToken")  # when using "NEWERTHAN" or "AFTER", you always get the absolute most recent logs, with now date should return no logs
            FinalId=$(get_lastactivity_id "$json_logs")
            StartId=$StartAtActId
        else
            echo "ERROR - [main] Invalid combination of first-run options was detected or invalid initial inputs. FirstRun:[$FirstRun] was true but StartAtActId:[$StartAtActId] and StartNow:[$StartNow] or StartDateTime:[$StartDateTime] was invalid."
            exit 3
        fi
    elif ! $FirstRun; then
        StartId=$(get_lastrun_from_state)  # get the last good log stored from state, this will be our starting point
        if [[ ! "$StartId" =~ $_NUM_REGEX ]]; then { StartId=$(read_config_file 'LASTRUN_ACTID'); } fi # try the backup, to be sure
    fi
    #local -i prev_first=$StartId
    local -i prev_last=$(( $StartId + $PageSize ))
    while true; do
        unset actids json_logs url
        url="${ApiEndpoint}?${filters}&olderThan=${StartId}&pageSize=$PageSize"
        json_logs=$(collect_logs "$url" "$AuthToken")
        IFS=' ' read -ra actids <<< "$(get_all_actids "$json_logs")"
        if [[ "${actids[0]}" != 'null' ]] && (( $StartId <= $FinalId )); then
            # deal with missing and overlapped log pulls
            local -i this_first=${actids[-1]} # first and lowest logid of this pull i.e. 19 or 29 for two sample pulls below, prev pulls are still last=19:first=6
            local -i this_last=${actids[0]} # last and highest logid of this pull i.e. 29 or 40 for two sample pulls below
            if (( this_first >= prev_last )); then # if the previous logpull was 6-19 and this logpull was 29-19, i.e., 19 == 19 (or 40-29: 29 > 28)
                readarray -t logarray < <(serialize_logs "$json_logs") # prep log array by converting list of logs to new array
                print_start=$(( $prev_last - $this_first + 1 )) # get the difference and add it to the 0-indexed print_start, i.e. 19-19+1=1, or 29-28+1=2
                for (( i=print_start; i<${#logarray[@]}; i++  )); do
                    echo "${logarray[$i]}" | tee -a "${TargetLogPath}/ninjaone_logs_$(date +"$TargetLogFormat").log"
                done
                prev_last=$this_last
                StartId=$(( $StartId + $PageSize ))
            else # if no overlap, just print out all the logs, no need for an expensive logarray
                echo "$json_logs" | serialize_logs | tee -a "${TargetLogPath}/ninjaone_logs_$(date +"$TargetLogFormat").log" && {
                    write_lastrun_to_state "$this_last" && update_config_file 'LASTRUN_ACTID' "${actids[0]}"
                    prev_last=$this_last
                    StartId=$(( $StartId + $PageSize ))
                }
            fi
        else
            echo "WARNING - [main] No more logs to collect:[${#actids[@]}] or our StartId id:[$StartId] reached the final stop id:[$FinalId]"
            break    
        fi
	    exlog=$(log_disk_usage_exceeded "$TargetLogPath")
        if $exlog; then # check if we are exceeding max disk usage for the disk, die if we are
            echo "ERROR - [main] Disk usage for target log directory:[$TargetLogPath] has exceeded the maximum allowed percentage of $MaxLogFilePercentage%. Exiting." >&2
            break
        fi
        local exptoken=$(check_token_expiration)
        if $exptoken && (( RetryCount <= MaxRetries )); then
            get_auth_token && RetryCount=$(( RetryCount + 1 ))
        elif (( RetryCount > MaxRetries )); then
            echo "ERROR - [main] Maximum retry attempts reached during log collection. Exiting." >&2
            break
        else
            echo "INFO - [main] Authentication token is still valid."
        fi    
    done
    local -i fin=$(get_lastrun_from_state)
    if (( $fin > 0 )); then { update_config_file 'FIRST_RUN' 'false'; } fi 
}

declare -i postat opterr
declare parsed_opts
[[ $# -eq 0 ]] && { echo -e "WARNING - No input parameters [$#] were found on stdin. Running with default settings."; }
getopt -T > /dev/null; opterr=$?  # check for enhanced getopt version
if (( $opterr == 4 )); then  # we got enhanced getopt
    declare Long_Opts=url-endpoint:,client-id:,start-at-actid:,start-at-datetime:,start-now,get-all-logs,page-size:,target-directory:,target-format:,filter-file:,credential-file:,force-first-run,debug,help 
    declare Opts=u:k:a:e:njp:t:l:f:c:rdh
    ! parsed_opts=$(getopt --longoptions "$Long_Opts" --options "$Opts" -- "$@") # load and parse options using enhanced getopt
    postat=${PIPESTATUS[0]}
else 
    ! parsed_opts=$(getopt u:k:a:e:njp:t:l:f:c:rdh "$@") # load and parse avail options using original getopt
    postat=${PIPESTATUS[0]}
fi
if (( $postat != 0 )) || (( $opterr != 4 && $opterr != 0 )); then # check return and pipestatus for errors
    echo -e "ERROR - invalid option was entered:[$*] or missing required arg."
    collector_usage
    exit 1 
else 
    eval set -- "$parsed_opts"  # convert positional params to parsed options ('--' tells shell to ignore args for 'set')
    while true; do 
        case "${1,,}" in
            -u|--url-endpoint )     { { [[ "$2" =~ $_URL_REGEX ]] && ApiEndpoint=$(san "$2"); }; shift 2; } ;;
            -k|--client-id )        { { [[ -n "$2" ]] && ClientId=$(san "$2"); }; shift 2; } ;;
            -a|--start-at-actid )   { { [[ "$2" =~ $_NUM_REGEX ]] && StartAtActId=$(san "$2"); }; shift 2; } ;;
            -e|--start-at-datetime ) { { [[ "$2" =~ $_DATE_FORMAT_REGEX ]] && StartDateTime=$(san "$2"); }; shift 2; } ;;
            -n|--start-now )        { StartNow=true; shift; } ;;
            -j|--get-all-logs )     { GetAllAvailableLogs=true; shift; } ;;
            -p|--page-size )        { if [[ "$2" =~ $_NUM_REGEX ]] && (( $2 > 0 && $2 <= MaxPageSize )); then { PageSize=$(san "$2"); } fi; shift 2; } ;;
            -t|--target-directory ) { { [[ -d "$2" ]] && TargetLogPath=$(san "$2"); }; shift 2; } ;;
            -l|--target-format )    { { [[ "$2" =~ $_DATE_FORMAT_REGEX ]] && TargetLogFormat=$(san "$2"); }; shift 2; } ;;
            -f|--filter-file )      { { [[ -f "$2" ]] && FilterFile=$(san "$2"); }; shift 2; } ;;
            -c|--credential-file )  { { [[ -f "$2" ]] && CredentialFile=$(san "$2"); }; shift 2; } ;;
            -r|--force-first-run ) { echo "INFO - [ninjaone_collector.sh] Forcing FirstRun mode. Existing configuration file will be backed up if it exists.";
                FirstRun=true; shift; } ;;
            -d|--debug ) { set -x; shift; } ;;
            -h|--help ) { collector_usage; shift; } ;;
            -- ) shift; break ;;  # end of options     
        esac
    done

fi
#collector_usage
main
