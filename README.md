# Autosploit
---
## EZ-Config Ready-To-Go Dockerized Noninteractive MetaSploit Framework

#### NOTICE - *Please use this tool repsonsibly and in accoredance with the law.*

## USAGE
This script will kick off a fairly-comprehensive noninteractive MetaSploit Framework scan of a host. With only minor modifications, you can use this tool in a wide variety of applications.

## DEFAULTS

The Project folder defaults to $HOME/mobile_sploit

The JSON Database export, $MSF_RESULT_FILE, defaults to $HOME/mobile_sploit/result.json

The scan target defaults to external-most ipv4 address on any local interface.

It defaults to noninteractive scanning of scan target

```
./autosploit.sh [SCAN_TARGET (defaults to external-most ipv4)] [MSF_WEB_PORT]
```

## REQUIREMENTS
```
docker
docker-compose
curl
wget
```

### RUNNING
**with curl** (noninteractive scan)
```
curl -s https://scripts.masonstelter.com/autosploit.sh | sudo bash -
```

**with wget** (noninteractive scan)
```
sudo bash $(wget -qO- https://masonstelter.com/scripts/autosploit.sh)
```

### RUNNING with customizations
**with git** (optional noninteractive scan)
```
git clone https://github.com/masonville17/autosploit && cd autosploit
```
and then change any of the configuration items.

#### MSF Scan Options
```
FINGER_USERS=true
PORTSCAN=true
SCAN_IPV6=false

SCAN_FTP=false
FTP_PORT=21

SCAN_RSYNC=false
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

SCAN_NETBIOS=false
SCAN_OTHER=false
```

#### User-Script-Invocation Options
```
NONINTERACTIVE=true
NONINTERACTIVE_SCAN_SCRIPT="noninteractive_scan.sh"

```
#### Configure how your user script is invoked and with which arguments
```
MSFCONSOLE_START_CMD="
./$NONINTERACTIVE_SCAN_SCRIPT "$SCAN_TARGET""
```

```NONINTERACTIVE_SCAN_SCRIPT```-> Name of user-script

```AUX_KALI_PACKAGES```-> Configure installation of any custom kali-rolling packages, space-seperated

```BUILD_IMAGE```-> Build image locally (reccomended) or pull-remote

```DOCKER_COMPOSE_UP_ARGS```-> arguments during docker compose up (-d, --remove-orphans, etc)

```LOGFILE_MAX_LINES```-> Number of lines in logfile, auto-trucated

```POSTGRES_PORT```-> Port for MSF postgresql service, default is 7777

