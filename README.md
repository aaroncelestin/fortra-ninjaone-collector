# fortra-ninjaone-collector
NinjaOne Activity Log Collector for Fortra SIEM 

DESCRIPTION:
This script installs an application that collects NinjaOne Activity logs from NinjaOne's API endpoint and saves them to a directory to send to a SIEM. When started, the default log collection datetime
is 24 hours before the start time. You may override this by using the '--start-now' or '--start-at-datetime SOMEDATE' switches. Most configuration options can be changed with command line switches. Any
configuration options set via cmd-line switches are stored in a config file for future runs. See the OPTIONS section below for which options can be set. You may also specify a custom configuration file
for the script to read your custom configuration variables and an optional filter file that will be used to build log filters by CLASS, TYPE and RESULT. See NinjaOne's Activity Log API documentation
here: https://app.ninjarmm.com/apidocs-beta/core-resources/operations/getActivities for more information. NinjaOne API access requires the following script variables to be set: Client ID, Client Secret,
and API Endpoint. You will be prompted to enter the Client ID and Client Secret during installation if not set in the environment or credential file. You may set the API auth variables in a file at
~/.ninjaone_collector and change the permissions to 0600 before running the script.

CONFIGURATION LIMITATIONS:
The script will also create a configuration file at: '/etc/ninjaone_collector_dt/app.conf' to store your configuration variables for future runs. You can change any variables in the configuration file
after installation and the script will use them on the next run. However, log rotation and systemd service settings can only be modified by running the reinstallion script again. Note these in the
options below: NOT Config file updateable.

STATE FILE:
The script will create a state file to track the last-stored log activity ID. This file is located at: '/etc/ninjaone_collector_dt/.lastrun.state'. Do not delete this file unless you want to re-collect
all logs from the beginning. If you want to change the starting activity ID, you may edit this file or use the --start-at-actid option on the command line.

API CREDENTIALS:
You may set the API auth variables: ClientId and ClientSecret in a file, although this is not recommended. Be sure to set the permissions of the creds file to 0600 before running the script. Then call
the installer script with the '--credential-file' option pointing to the path to the credential file.

INSTALLATION:
This script must be run with sudo privileges (i.e. sudo bash scriptname.sh) to install the systemd service and timer. If you cannot use sudo privileges, you may set up this app as a cron job instead of
as a systemd service.

UNINSTALLATION:
To uninstall the collector, run the script with the '--uninstall' option. This will stop and disable the systemd service and timer, remove the service and timer files, and delete the configuration and
state files. It will not delete the log files in the target directory.

ACCEPTED DATE FORMATS:
The script uses GNUs date utility to parse many string date formats, all of which are too numerous to list here. All separators are supported: (-|.|_|/|,), spaces are allowed, dates can be in any order
and the month can be strings like 'January', 'Feb', 'Mar', etc. Strongly recommend you use ZULU time for Timezones unless you know what you are doing.
If you are not sure about the date format, try the simplest format: 'September 27, 2025 3:00PM'. The script will use the date utility to parse the string and set the start datetime. For more on date
formats, highly recommend you read the GNU documentation here: https://www.gnu.org/software/coreutils/manual/html_node/Date-input-formats.html

EXAMPLES:
$_> sudo bash install_ninjaone_collector_dt.sh --start-at-datetime 'Sept 25, 2025 3:00PM' --page-size '500' --target-format 'DD-MM-YY' --filter-file './filters.txt'

$_> sudo ./install_ninjaone_collector_dt.sh --url-endpoint 'https://us2.ninjarmm.com/v2/activities' --target-directory '/var/logs/ninjaone' --filter-file './filters.txt'

$_> sudo bash install_ninjaone_collector_dt.sh --config-file './custom_config.conf' --max-log-age '90' --log-rotation-interval 'weekly' --log-rotate-timer '12' --run-interval '30'

$_> sudo ./install_ninjaone_collector_dt.sh --credential-file '/path/to/credsfile' --config-file './custom_config.conf' --force-first-run --run-onboot-time '10'

$_> install_ninjaone_collector_dt.sh --help


NOTE: Most special characters entered for filenames or paths will be ignored or removed IMMEDIATELY to avoid issues with script operation. Only alphanumeric characters and the following characters are al
lowed:[ / . - _ : + ]

SERVICE AND TIMER MANAGEMENT:
Service Control Options:
        'sudo systemctl start|stop|restart|status ninjaone_collector_dt.service'
Service Management Options:
        'sudo systemctl enable|disable ninjaone_collector_dt.service'
Timer Control Options:
        'sudo systemctl start|stop|restart|status ninjaone_collector_dt.timer'
Timer Management Options:
        'sudo systemctl enable|disable ninjaone_collector_dt.timer'

OPTIONS:
+----+------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------+
|Shrt|Long Opts               |Description                                                                                                                                          |
+----+------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------+
|  -u|--url-endpoint          |Specify the NinjaOne API endpoint URL. Default is 'https://us2.ninjarmm.com/v2/activities'. This can be changed in the config file later.            |
|  -k|--client-id             |Specify your NinjaOne API Client ID. You will be prompted to enter this if not set in the environment or credential file.                            |
|  -i|--run-interval          |Specify the interval in minutes between runs of the service that starts the collector. Default is '15'. NOT Config file updateable.                  |
|  -b|--run-onboot-time       |Specify the time in minutes to wait after boot before first run of the service that starts the collector. Default is '5'. NOT Config file updateable.|
|  -g|--max-log-age           |Specify the max age in days to keep old log files. Default is '60'. NOT Config file updateable.                                                      |
|  -y|--log-rotation-interval |Specify the log rotation interval. Default is 'daily'. NOT Config file updateable.                                                                   |
|  -z|--log-rotate-timer      |Specify the log rotation timer in days. Default is '30'. NOT Config file updateable.                                                                 |
|  -c|--config-file           |Specify the path to your intitial configuration file. Once installed location will be '/etc/ninjaone_collector_dt/app.conf'.                         |
|  -s|--start-at-actid        |Specify the start activity ID to begin collection at. Default start activity ID is 1 on the FirstRun.                                                |
|  -m|--start-at-datetime     |Specify the start datetime to begin collection at. See notes for accepted formats. Default start datetime is 1 day ago.                              |
|  -n|--start-now             |Specify to begin collection now at installation time and ignore any previous logs.                                                                   |
|  -j|--get-all-logs          |Get all logs from the beginning of time. This will cause the collector to run for a long time.                                                       |
|  -p|--page-size             |Specify the number of logs to retrieve per API call. Default is 200. Max is 1000. Config file updateable.                                            |
|  -t|--target-directory      |Specify the directory to save collected logs. Default is '/var/log/ninjaone_collector_dt'. Config file updateable.                                   |
|  -l|--target-format         |Specify the log file date format. Default is 'YYYYMMDD'. Config file updateable.                                                                     |
|  -f|--filter-file           |Specify the path to a filter file containing a list of custom filters. Config file updateable.                                                       |
|  -a|--credential-file       |Specify the path to your credential file. Default is '/var/lib/ninjaone_collector_dt/.ssl/.apiinfo'. Config file updateable.                         |
|  -r|--force-first-run       |Force the collector to run in FirstRun mode, backing up existing user config if it exists. Config file updateable.                                   |
|  -x|--uninstall             |Uninstall the collector. This will stop-disable-delete the systemd service and timer and remove all files including auth config and state artefacts. |
|  -d|--debug                 |Enable debug mode for verbose output.                                                                                                                |
|  -h|--help                  |Display this help message and exit.                                                                                                                  |
+----+------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------+
