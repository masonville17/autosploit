#!/bin/bash
# from_scratch.sh -
# Usage: ./from_scratch.sh [SCAN_TARGET] [MSF_WEB_PORT]
set -e
PROJECT="mobile_sploit"
PROJECT_VERSION="0.1.4"
PROJECT_FOLDER="$HOME/$PROJECT"
SCAN_TARGET=${1:-$(curl -s https://ipinfo.io/ip)}
MSF_WEB_PORT="${2:-4444}"
echo "Whoa, What's that? It almost glanced me! It was $PROJECT:$PROJECT_VERSION... Scan target is $SCAN_TARGET"

INSTANTIATION_TIME=$(date +%s)
NONINTERACTIVE=true
NONINTERACTIVE_SCAN_SCRIPT="noninteractive_scan.sh"
MSFCONSOLE_START_CMD="
./$NONINTERACTIVE_SCAN_SCRIPT "$SCAN_TARGET""
# MSF Auto-Scan Options
##########################################################################
FINGER_USERS=true
PORTSCAN=true
SCAN_IPV6=true

SCAN_FTP=true
FTP_PORT=21

SCAN_RSYNC=true
RSYNC_PORT=2222

SCAN_RSH=true
RSH_PORT=513

SCAN_RSERVICES=true
RSERVICES_PORT=443

SCAN_REDIS=true
REDIS_PORT=6379

SCAN_UDP=true
UDP_PORT=53

SCAN_ETCD=true
ETCD_PORT=2379

SCAN_NTP=true
NTP_PORT=1023

SCAN_AUX_NTP=true
AUX_NTP_PORT=123

SCAN_NETBIOS=true
SCAN_OTHER=true
##########################################################################
AUX_KALI_PACKAGES="nmap net-tools apt-transport-https ca-certificates curl gnupg-agent software-properties-common libpq5 postgresql-client \
  postgresql postgresql-contrib libpq-dev libpcap-dev libsqlite3-dev zlib1g-dev libxml2-dev libxslt1-dev libffi-dev ruby-dev \
  git curl wget build-essential nmap dnsrecon nmap masscan whatweb wafw00f sslscan gobuster amass sublist3r enum4linux \
  smbclient smbmap exploitdb shellter veil mingw-w64 wine python3-impacket hydra john hashcat patator medusa seclists sqlmap \
  xsser wfuzz ffuf davtest nikto sqlite3 jq net-tools tcpdump wireshark tshark evil-winrm crackmapexec powersploit bloodhound responder"
BUILD_IMAGE=true
DOCKER_COMPOSE_UP_ARGS="-d --remove-orphans"
# DOCKER_COMPOSE_VERB="docker compose" # Leave unset to find automatically.
# PATHS -- local
LOCAL_USER_SCRIPTS_FOLDER="$PROJECT_FOLDER/user_scripts"
ENV_FILE="$PROJECT_FOLDER/$PROJECT.env"
COMPOSE_FILE="$PROJECT_FOLDER/docker-compose.yml"
LOCAL_MSF_HOST_LOGFILE_PATH="$PROJECT_FOLDER/$PROJECT.log"
LOCAL_DATABASE_CONFIG="$PROJECT_FOLDER/database.yml"
LOCAL_RESULT_FILE="$PROJECT_FOLDER/result.json"
rm -rf "$PROJECT_FOLDER" && mkdir -p "$LOCAL_USER_SCRIPTS_FOLDER" && touch $LOCAL_MSF_HOST_LOGFILE_PATH
# LOGGING
LOGFILE_MAX_LINES=4000
# Define some functions
##########################################################################
function sanitize_hostname() {
  echo "${1:-msf}" | tr '_' '-' | sed -E 's/[^a-zA-Z0-9.-]//g; s/^-+|-+$//g' | awk -F'.' '{for (i=1; i<=NF; i++) if (length($i) > 63) $i = substr($i, 1, 63); print $0;}' | cut -c1-255 | tr '[:upper:]' '[:lower:]'
}
function print_and_log() {
    local message="$1"
    echo "$message"    
    echo "$(date) - $HOST - $message" >> "$LOCAL_MSF_HOST_LOGFILE_PATH"
    if [ $(wc -l < "$LOCAL_MSF_HOST_LOGFILE_PATH") -gt $LOGFILE_MAX_LINES ]; then
        tail -n $LOGFILE_MAX_LINES "$LOCAL_MSF_HOST_LOGFILE_PATH" > "$LOCAL_MSF_HOST_LOGFILE_PATH.tmp" && mv "$LOCAL_MSF_HOST_LOGFILE_PATH.tmp" "$LOCAL_MSF_HOST_LOGFILE_PATH"
    fi
}
print_and_log "Startup Environment Checks... Docker..."
if [[ -z "$DOCKER_COMPOSE_VERB" ]]; then
  if ! command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE_VERB="docker compose"
  else
    DOCKER_COMPOSE_VERB="docker-compose"
  fi
  print_and_log "Docker compose was found to be $DOCKER_COMPOSE_VERB."
else
  print_and_log "Docker compose is set to $DOCKER_COMPOSE_VERB, skipping check."
fi
if ! command -v docker &>/dev/null ; then
  print_and_log "Docker or Docker Compose not installed. Please install them before running this script."
  exit 1
fi
check_required_vars() {
  local paths_array=$1
  for var in "${paths_array[@]}"; do
    if [[ -z $var ]]; then
      echo "[ERROR] Variable $var is empty or not set."
      return 1
    fi
  done
  return 0
}
# Determine / Santize Hostnames
##########################################################################
print_and_log "Determining Hostnames and config..."
MSF_HOST="$(sanitize_hostname $PROJECT)"
MSF_DB="msf"
POSTGRES_HOST="$MSF_HOST-db"
print_and_log "MSF_HOST: $MSF_HOST, MSF_DB: $MSF_DB, POSTGRES_HOST: $POSTGRES_HOST"

# Readying Docker Environment
print_and_log "Readying Docker Environment..."
print_and_log "docker stop MSF...$(docker ps -q --filter name=$MSF_HOST | xargs -r docker stop | xargs -r docker rm)"
print_and_log "docker stop Postgresql...$(docker ps -q --filter name=$POSTGRES_HOST | xargs -r docker stop | xargs -r docker rm)"
print_and_log "docker builder/system prune... $(docker builder prune -af && docker system prune -af)"

#POSTGRES Configuration
POSTGRES_PORT=5432
PASSWORDLESS_POSTGRES=false
POSTGRES_USER=postgres
POSTGRES_DB=postgres
POSTGRES_PASSWORD=${PGPASSWORD:-"${POSTGRES_DB}password"}
POSTGRES_POOL=10
POSTGRES_TIMEOUT=20
POSTGRES_DATA_DIR="/var/lib/postgresql/data"
POSTGRES_SOCKET_DIR="/var/run/postgresql"

# DOCKER STUFF
POSTGRES_VOLUME_NAME="$POSTGRES_HOST-volume"
MSF_VOLUME_NAME="$MSF_HOST-volume"
CONTAINER_RESTART="unless-stopped"
POSTGRES_IMAGE_TAG="16.2-alpine"
#MSF Configuration
# PATHS -- msf container
MSF_CONFIG_FOLDER="/root/.msf4"
MSF_RESOURCE_TEMPATE="allscanners.rc"
MSF_RESULT_FILE="$MSF_CONFIG_FOLDER/result.json"
MSF_HOST_LOGFILE_PATH="$MSF_CONFIG_FOLDER/$PROJECT.log"
MSF_DATABASE_CONFIG="$MSF_CONFIG_FOLDER/database.yml"
MSF_IMAGE_TAG="STANDALONE-latest"
MSF_DATABASE="msf"
MSF_DATABASE_USER="msf"
MSF_DATABASE_URL="postgres://$MSF_DATABASE_USER:$MSF_PASSWORD@${POSTGRES_SOCKET_DIR:-$POSTGRES_HOST}:$POSTGRES_PORT/$MSF_DATABASE"

SETUP_TIME=$(date +%s)
#BEGIN SETUP
##########################################################################
print_and_log "
Instantiated at $INSTANTIATION_TIME, set to run against $SCAN_TARGET.
  BUILD_IMAGE (docker, build local vs pull remote) is set to: $BUILD_IMAGE
  PROJECT_FOLDER (local) will be: $PROJECT_FOLDER
  DOCKER_COMPOSE_VERB (local) will be: $DOCKER_COMPOSE_VERB
  SCAN_TARGET will be: $SCAN_TARGET
  MSF hostname will be: $MSF_HOST
  MSF_DB will be: $MSF_DB
  POSTGRES_HOST will be: $POSTGRES_HOST
  ENV_FILE (local, all) will be: $ENV_FILE
  LOCAL_DATABASE_CONFIG (local, for msf) will be: $LOCAL_DATABASE_CONFIG
  LOCAL_MSF_HOST_LOGFILE_PATH (local) will be: $LOCAL_MSF_HOST_LOGFILE_PATH
  LOCAL_USER_SCRIPTS_FOLDER (local, for msf) will be: $LOCAL_USER_SCRIPTS_FOLDER
  ----------------------------------------------------------------
"

if [[ "$NONINTERACTIVE" != "true" ]]; then
print_and_log "Press enter now or enter CTL+C to exit and change settings. Project Dir at $PROJECT_FOLDER will be overwritten, 
Please choose a new project directory if running multiple seperate concurrent scans."
read
fi

# Determine / Santize Hostnames
##########################################################################
print_and_log "Ensuring local paths and files..."
REQUIRED_LOCAL_PATHS=("$PROJECT_FOLDER" "$LOCAL_USER_SCRIPTS_FOLDER" "$ENV_FILE" "$COMPOSE_FILE" "$LOCAL_MSF_HOST_LOGFILE_PATH" "$LOCAL_DATABASE_CONFIG")
check_required_vars $REQUIRED_LOCAL_PATHS || exit 1

touch "$ENV_FILE" \
    "$COMPOSE_FILE" \
    "$LOCAL_MSF_HOST_LOGFILE_PATH" \
    "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE" \
    "$LOCAL_USER_SCRIPTS_FOLDER/$NONINTERACTIVE_SCAN_SCRIPT" \
    "$LOCAL_MSF_HOST_LOGFILE_PATH.tmp" \
    "$LOCAL_RESULT_FILE"
# Clean and prepare directories

# Determine / Santize Hostnames
##########################################################################
print_and_log "Determining Build Strategy..."
if [[ "$BUILD_IMAGE" != "true" ]]; then
  print_and_log "Using Pre-Built Image for $Project"
  MSF_IMAGE_SOURCE="image: masonville17/$PROJECT:$MSF_IMAGE_TAG"
  DOCKER_COMPOSE_UP_ARGS="$DOCKER_COMPOSE_UP_ARGS"
else
  DOCKER_COMPOSE_UP_ARGS="--build $DOCKER_COMPOSE_UP_ARGS"
  print_and_log "Generating Dockerfile for building $Project"
  MSF_IMAGE_SOURCE="build:
      context: $PROJECT_FOLDER
      dockerfile: Dockerfile"
print_and_log "Generating Dockerfile at $PROJECT_FOLDER/Dockerfile"
cat << EOF > "$PROJECT_FOLDER/Dockerfile"
FROM kalilinux/kali-rolling
COPY msfstart.sh .
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt -y upgrade && \
	apt install -y  metasploit-framework $AUX_KALI_PACKAGES && \
  mkdir -p "$MSF_CONFIG_FOLDER" "$LOCAL_USER_SCRIPTS_FOLDER" \
  touch "$MSF_HOST_LOGFILE_PATH" "$MSF_RESULT_FILE" && \
	chmod +x msfstart.sh
VOLUME "$MSF_CONFIG_FOLDER", "$POSTGRES_SOCKET_DIR", "$POSTGRES_DATA_DIR"
ENTRYPOINT [ "bash", "./msfstart.sh" ]
EOF
fi

# Generate Docker Compose file
##########################################################################
print_and_log "Generate Docker Compose file at $COMPOSE_FILE"
cat << EOF > "$COMPOSE_FILE"
services:
  "$MSF_HOST":
    hostname: "$MSF_HOST"
    container_name: "$MSF_HOST"
    $MSF_IMAGE_SOURCE
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_ADMIN
    env_file: "$ENV_FILE"
    network_mode: bridge
    volumes:
      - "$POSTGRES_SOCKET_DIR:$POSTGRES_SOCKET_DIR"
      - "$POSTGRES_VOLUME_NAME:$POSTGRES_DATA_DIR"
      - "$LOCAL_USER_SCRIPTS_FOLDER:/user_scripts"
      - "$MSF_VOLUME_NAME:/$MSF_CONFIG_FOLDER:rw"
      - "$ENV_FILE:$MSF_CONFIG_FOLDER/$PROJECT.env:ro"
    privileged: true
    security_opt:
      - seccomp:unconfined
    depends_on:
      - $POSTGRES_HOST
    links:
      - $POSTGRES_HOST
    ports:
      - "$MSF_WEB_PORT:4444"
    restart: "$CONTAINER_RESTART"

  "$POSTGRES_HOST":
    hostname: "$POSTGRES_HOST"
    container_name: "$POSTGRES_HOST"
    image: "postgres:$POSTGRES_IMAGE_TAG"
    volumes:
      - "$POSTGRES_SOCKET_DIR:$POSTGRES_SOCKET_DIR"
      - "$POSTGRES_VOLUME_NAME:$POSTGRES_DATA_DIR"
    env_file: "$ENV_FILE"
    network_mode: bridge
    restart: "$CONTAINER_RESTART"

volumes:
  $POSTGRES_VOLUME_NAME:
    driver: local
  $MSF_VOLUME_NAME:
EOF

# Generate environment file
print_and_log "generating env file at $ENV_FILE"
cat << EOF > "$ENV_FILE"
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PORT=$POSTGRES_PORT
POSTGRES_DB=$POSTGRES_DB
MSF_DB=$MSF_DB
POSTGRES_USER=$POSTGRES_USER
MSF_DATABASE_USER=$MSF_DATABASE_USER
MSF_DATABASE_URL=$MSF_DATABASE_URL
POSTGRES_POOL=$POSTGRES_POOL
POSTGRES_TIMEOUT=$POSTGRES_TIMEOUT
MSF_CONFIG_FOLDER=$MSF_CONFIG_FOLDER
MSF_DATABASE_CONFIG=$MSF_DATABASE_CONFIG
POSTGRES_SOCKET_DIR=$POSTGRES_SOCKET_DIR
POSTGRES_DATA_DIR=$POSTGRES_DATA_DIR
MSF_CONFIG_FOLDER=$MSF_CONFIG_FOLDER
NONINTERACTIVE=$NONINTERACTIVE
MSFCONSOLE_START_CMD="$MSFCONSOLE_START_CMD"
NONINTERACTIVE_SCAN_SCRIPT=$NONINTERACTIVE_SCAN_SCRIPT
MSF_RESOURCE_TEMPATE=$MSF_RESOURCE_TEMPATE
LOCAL_RESULT_FILE=$LOCAL_RESULT_FILE
EOF


print_and_log "Generating MSF resource template at $LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
cat << EOF > "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
db_status
EOF

if [[ "$SCAN_FTP" == "true" ]]; then
print_and_log "FTP Scans are on (SCAN_FTP:$SCAN_FTP). FTP_PORT: $FTP_PORT"
echo "setg RPORT $FTP_PORT
use auxiliary/scanner/ftp/anonymous
run
use auxiliary/scanner/ftp/bison_ftp_traversal
run
use auxiliary/scanner/ftp/colorado_ftp_traversal
run
use auxiliary/scanner/ftp/easy_file_sharing_ftp
run
use auxiliary/scanner/ftp/ftp_login
run
use auxiliary/scanner/ftp/ftp_version
run
use auxiliary/scanner/ftp/konica_ftp_traversal
run
use auxiliary/scanner/ftp/pcman_ftp_traversal
run
use auxiliary/scanner/ftp/titanftp_xcrc_traversal
run
use auxiliary/scanner/gopher/gopher_gophermap
run" >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_RSYNC" == "true" ]]; then
print_and_log "RSYNC Scans are on (SCAN_RSYNC:$SCAN_RSYNC). RSYNC_PORT: $RSYNC_PORT"
echo "setg RPORT $RSYNC_PORT
use auxiliary/scanner/rsync/modules_list
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_RSH" == "true" ]]; then
print_and_log "RSH Scans are on (SCAN_RSH:$SCAN_RSH). RSH_PORT: $RSH_PORT"
echo "setg RPORT $RSH_PORT
use auxiliary/scanner/rservices/rsh_login
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_RSERVICES" == "true" ]]; then
print_and_log "RServices Scans are on (SCAN_RSERVICES:$SCAN_RSERVICES). RSERVICES_PORT: $RSERVICES_PORT"
echo "setg RPORT $RSERVICES_PORT 
use auxiliary/scanner/rservices/rexec_login
run
use auxiliary/scanner/rservices/rlogin_login
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_REDIS" == "true" ]]; then
print_and_log "Redis Scans are on (SCAN_REDIS:$SCAN_REDIS). REDIS_PORT: $REDIS_PORT"
echo "set RPORT $REDIS_PORT
use auxiliary/scanner/redis/file_upload
run
use auxiliary/scanner/redis/redis_login
run
use auxiliary/scanner/redis/redis_server
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_UDP" == "true" ]]; then
print_and_log "UDP Scans are on (SCAN_UDP:$SCAN_UDP). UDP_PORT: $UDP_PORT"
echo "setg RPORT $UDP_PORT
use auxiliary/scanner/discovery/udp_probe
run
use auxiliary/scanner/discovery/udp_sweep
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_IPV6" == "true" ]]; then
print_and_log "IPV6 Scans are on (SCAN_IPV6:$SCAN_IPV6)"
echo "use auxiliary/scanner/discovery/ipv6_multicast_ping
run
use auxiliary/scanner/discovery/ipv6_neighbor
run
use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_ETCD" == "true" ]]; then
print_and_log "ETCD Scans are on (SCAN_ETCD:$SCAN_ETCD). ETCD_PORT: $ETCD_PORT"
echo "setg RPORT $ETCD_PORT
use auxiliary/scanner/etcd/open_key_scanner
run
use auxiliary/scanner/etcd/version
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$FINGER_USERS" == "true" ]]; then
print_and_log "Finger Users is on (FINGER_USERS:$FINGER_USERS)."
echo "setg RPORT 22
use auxiliary/scanner/finger/finger_users
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_NTP" == "true" ]]; then
print_and_log "NTP Scans on (SCAN_NTP:$SCAN_NTP) NTP_PORT: $NTP_PORT"
echo "setg RPORT $NTP_PORT
use auxiliary/scanner/ntp/ntp_monlist
run
use auxiliary/scanner/ntp/ntp_nak_to_the_future
run
use auxiliary/scanner/ntp/ntp_peer_list_dos
run
use auxiliary/scanner/ntp/ntp_peer_list_sum_dos
run
use auxiliary/scanner/ntp/ntp_readvar
run
use auxiliary/scanner/ntp/ntp_req_nonce_dos
run
use auxiliary/scanner/ntp/ntp_reslist_dos
run
use auxiliary/scanner/ntp/ntp_unsettrap_dos
run
use auxiliary/scanner/ntp/timeroast
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_AUX_NTP" == "true" ]]; then
print_and_log "AUX NTP Scans on (SCAN_AUX_NTP:$SCAN_AUX_NTP) AUX_NTP_PORT: $AUX_NTP_PORT"
echo "setg RPORT $AUX_NTP_PORT
use auxiliary/scanner/ntp/ntp_monlist
run
use auxiliary/scanner/ntp/ntp_nak_to_the_future
run
use auxiliary/scanner/ntp/ntp_peer_list_dos
run
use auxiliary/scanner/ntp/ntp_peer_list_sum_dos
run
use auxiliary/scanner/ntp/ntp_readvar
run
use auxiliary/scanner/ntp/ntp_req_nonce_dos
run
use auxiliary/scanner/ntp/ntp_reslist_dos
run
use auxiliary/scanner/ntp/ntp_unsettrap_dos
run
use auxiliary/scanner/ntp/timeroast
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_NETBIOS" == "true" ]]; then
print_and_log "NetBIOS Scans are on (SCAN_NETBIOS:$SCAN_NETBIOS)."
echo "setg RPORT 443
use auxiliary/scanner/nntp/nntp_login
run
setg RPORT 119
use auxiliary/scanner/nntp/nntp_login
run
setg RPORT 137
use auxiliary/scanner/netbios/nbname
run
setg RPORT 138
use auxiliary/scanner/netbios/nbname
run
setg RPORT 139
use auxiliary/scanner/netbios/nbname
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$PORTSCAN" == "true" ]]; then
print_and_log "Port Scans are on (PORTSCAN:$PORTSCAN)."
echo "use auxiliary/scanner/portscan/ack
run
use auxiliary/scanner/portscan/ftpbounce
run
use auxiliary/scanner/portscan/syn
run
use auxiliary/scanner/portscan/tcp
run
use auxiliary/scanner/portscan/xmas
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

if [[ "$SCAN_OTHER" == "true" ]]; then
print_and_log "Other Scans are on (SCAN_OTHER:$SCAN_OTHER)."
echo "use auxiliary/scanner/http/web_vulndb
run
use auxiliary/scanner/http/wangkongbao_traversal
run"  >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"
fi

# Add Logging-Outfile to very end. (json file)
echo "db_export \"$MSF_RESULT_FILE\"" >> "$LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE"

# CAT-EOF Noninteractive Scan Script
##########################################################################
print_and_log "generating noninteractive scan script"
cat << EOF > "$LOCAL_USER_SCRIPTS_FOLDER/$NONINTERACTIVE_SCAN_SCRIPT"
#!/bin/bash
scan_host="\$1"
host_rc_file="./\$1.rc"
all_scanners="$(cat $LOCAL_USER_SCRIPTS_FOLDER/$MSF_RESOURCE_TEMPATE)"
echo "\$all_scanners"
echo "setg RHOSTS \$scan_host" > "\$host_rc_file"
echo "\$all_scanners" >> "\$host_rc_file"
echo "scanning \$scan_host"
stty -echo 2>/dev/null && msfconsole -r "\$host_rc_file"
EOF
  # host: ${POSTGRES_SOCKET_DIR:-$POSTGRES_HOST}
# Generate environment file

# APPEND PASSWORD/AUTH_METHOD depending on PASSWORDLESS_POSTGRES
##########################################################################
print_and_log "Passwordless postgres set to $PASSWORDLESS_POSTGRES... "
if [[ "$PASSWORDLESS_POSTGRES" != "true" ]]; then
    print_and_log "Setting POSTGRES_PASSWORD in .env- $ENV_FILE"
    echo "PGPASSWORD=$POSTGRES_PASSWORD" >> "$ENV_FILE"
    echo "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" >> "$ENV_FILE"  
  else
    print_and_log "Setting POSTGRES_HOST_AUTH_METHOD=trust in .env- $ENV_FILE"
    echo "POSTGRES_HOST_AUTH_METHOD=trust" >> "$ENV_FILE"
    echo "PGPASSWORD=" >> "$ENV_FILE"
    echo "POSTGRES_PASSWORD=" >> "$ENV_FILE"  
fi

# CAT-EOF Docker Entrypoint (msfstart.sh)
##########################################################################
print_and_log "generating docker entrypoint at msfstart.sh"
cat << EOF > "./msfstart.sh"
#!/bin/bash
set -a
print_and_log "Starting MSF Container @$(date +%s)"
function sanitize_hostname() {
  echo "\${1:-msf}" | tr '_' '-' | sed -E 's/[^a-zA-Z0-9.-]//g; s/^-+|-+$//g' | awk -F'.' '{for (i=1; i<=NF; i++) if (length($i) > 63) $i = substr($i, 1, 63); print $0;}' | cut -c1-255 | tr '[:upper:]' '[:lower:]'
}
print_and_log() {
    local message="\$1"
    echo "\$message"    
    echo "$(date) - \$HOST - \$message" >> "\$MSF_HOST_LOGFILE_PATH"
    if [ $(wc -l < "\$MSF_HOST_LOGFILE_PATH") -gt $LOGFILE_MAX_LINES ]; then
        tail -n \$LOGFILE_MAX_LINES "\$MSF_HOST_LOGFILE_PATH" > "\$MSF_HOST_LOGFILE_PATH.tmp" && mv "\$MSF_HOST_LOGFILE_PATH.tmp" "\$MSF_HOST_LOGFILE_PATH"
    fi
}
export MSF_HOSTNAME=\$(sanitize_hostname "\${MSF_HOSTNAME:-msf}")
export POSTGRES_HOST=\$(sanitize_hostname "\${POSTGRES_HOST:-\$MSF_HOSTNAME-db}")
export RAILS_ENV=\${RAILS_ENV:-production}
export RACK_ENV=\${RACK_ENV:-production}
export POSTGRES_PASSWORD=\${POSTGRES_PASSWORD:-msfpassword}
export PGPASSWORD=\${POSTGRES_PASSWORD:-msfpassword}
export MSF_CONFIG_FOLDER=\${MSF_CONFIG_FOLDER:-/root/.msf4}
export MSF_DATABASE_CONFIG=\${MSF_DATABASE_CONFIG:-\$MSF_CONFIG_FOLDER/database.yml}
export POSTGRES_USER=\${POSTGRES_USER:-msf}
export POSTGRES_POOL=\${POSTGRES_POOL:-5}
export POSTGRES_PORT=\${POSTGRES_PORT:-5432}
export PASSWORDLESS_POSTGRES=\${PASSWORDLESS_POSTGRES:-true}
export POSTGRES_DB=\${POSTGRES_DB:-msf}
export POSTGRES_TIMEOUT=\${POSTGRES_TIMEOUT:-60}
export POSTGRES_SOCKET_DIR="\${POSTGRES_SOCKET_DIR:-'/var/run/postgresql'}"
if [[ -S "\$POSTGRES_SOCKET_DIR/.s.PGSQL.5432" ]]; then
  POSTGRES_HOST="\$POSTGRES_SOCKET_DIR"
  print_and_log "Postgres Users: \$MSF_DB_USER and \$POSTGRES_USER"
  print_and_log "Socket for postgres found at \$POSTGRES_SOCKET_DIR, assuming local connection."
else
  print_and_log "Socket for postgres not found, assuming TCP/IP connection."
fi
if [[ "\$PASSWORDLESS_POSTGRES" == "true" ]]; then
    export POSTGRES_HOST=localhost
    export POSTGRES_HOST_AUTH_METHOD=trust
    export POSTGRES_PASSWORD=
    export PGPASSWORD=
else
    export POSTGRES_USER="postgres"
    export POSTGRES_PASSWORD="\$POSTGRES_PASSWORD"
    export PGPASSWORD="\$POSTGRES_PASSWORD"
fi
until psql -U postgres -d postgres -c "SELECT 1;" >/dev/null 2>&1; do
  print_and_log "[-] PostgreSQL is unavailable @- postgres://\$POSTGRES_USER:{password_redacted}@\$POSTGRES_HOST:\$POSTGRES_PORT/\$POSTGRES_DB"
  sleep 5
done
if [[ -f "\$MSF_DATABASE_CONFIG" ]]; then
  print_and_log "\$MSF_DATABASE_CONFIG Exists."
elif [[ -d "\$MSF_DATABASE_CONFIG" ]]; then
  print_and_log "\$MSF_DATABASE_CONFIG is a Directory. Empty host-side binding, remove."
  rm -rf "\$MSF_DATABASE_CONFIG" && msfdb init
else
  print_and_log "MSF_DATABASE_CONFIG doesnt' exist yet, init."
  msfdb init
fi
if [[ -z \$MSFCONSOLE_START_CMD ]]; then
    print_and_log "NONINTERACTIVE: \$NONINTERACTIVE"
    print_and_log "MSFCONSOLE_START_CMD: \$MSFCONSOLE_START_CMD"
    print_and_log "NONINTERACTIVE_SCAN_SCRIPT: \$NONINTERACTIVE_SCAN_SCRIPT"
    print_and_log "If command is empty we won't noninteractively run anything, then exec in and have fun!"
else
    print_and_log "Running MSFCONSOLE_START_CMD: \$MSFCONSOLE_START_CMD"
    print_and_log "NONINTERACTIVE: \$NONINTERACTIVE"
    print_and_log "MSFCONSOLE_START_CMD: \$MSFCONSOLE_START_CMD"
    print_and_log "NONINTERACTIVE_SCAN_SCRIPT: \$NONINTERACTIVE_SCAN_SCRIPT"
    cd /user_scripts && chmod +x "\$NONINTERACTIVE_SCAN_SCRIPT" 
    eval "\$MSFCONSOLE_START_CMD"
fi
# Keep the container running
exec tail -f /dev/null
EOF
chmod +x msfstart.sh

# BUILD and/or START!
##########################################################################
if [[ "$BUILD_IMAGE" != "true" ]]; then
  print_and_log "Pulling Docker Images for 'masonville17/$PROJECT:$MSF_IMAGE_TAG'"
else
  print_and_log "Building Docker image locally with dockerfile / context:
$MSF_IMAGE_SOURCE"
fi
eval "$DOCKER_COMPOSE_VERB up $DOCKER_COMPOSE_UP_ARGS"