#!/bin/bash
set -euo pipefail

cleanup() {
    stop_chat_server 2>/dev/null || true
    if mountpoint -q "$RAMDISK_DIR"; then
        sudo umount "$RAMDISK_DIR" || true
    fi
}

trap cleanup EXIT

# --------------------------------------
# Function: Display Venetian Mask
# --------------------------------------

display_venetian_mask() {
    clear
    echo -e "\e[1;34m"
    cat << "EOF"
                                        ..........,''........   .,:,'',;;,:;....'.........................                                          
                                       ...........,,... .'..''.....'';c..oo;:c'................................                                       
                                    ............;c,. .'...'........';::,;ddlcc,........,............  ..............                                  
                                   ............'dd'...,,. ...'''..';cooodllxo:;'.'''..',. .'.'.... .    ................                              
                                .. ..........''.,;,'',;,..',,'...;:;ckkdxxkkoc:::,;:;'.,'.......         ................                             
                               .........',,,,'.'',;;'.'...''',;,:ooddodddxxool:;cc;,,',:c:,........       ...     .........                           
                               ........',;:;::;:c;::,.','..,:::lxO0Oxxldklccddc;c:,;'..'',,,,,'.......                ........                        
                              ......''..,;::lol:',,'..';'.,:ldxOOKNOloldxodxxlolco:,......,,,,,,'''''...                 .......                      
                             .....',''..,clc:lc:;;;'.';;,;lxxxk0KNWNklkKOoxOdodcld:;. .  ..,;;;,,;:c;,'..        ...      ........                    
                             .....;:;:c,'::;odcc,,,'''.':oddO0KXNWWN0kOKK0Okdxdcd:.,.     .','',coocl:,''.....   .....     .......                    
                           .......';:l:.';,:kc,;,,'.,;,:ollkXNXNWNWXxk0k0X0O0Kddk;.    .   .,'':lc;od;.'''.....  ..         .......                   
                          ....... ..';'',..;c,';,,..;cccoodk0KKXWWWXooOOKXkokOcoOc.  ....  .....,,,,'...'......             ........                  
                        .........  .....,;,';:'.,,..;c;:lodxOXXNWWWWKxxO0kxkKOcx0l','....   ..................              ..........                
                        ........... ....',,,,''''..,:;;:codkKXKXNNNWWWWWWNNNWNXXXd,,'...    ...............               ............                
                       .............  .,'''';,.';;;:;;;:lddOXXkxKNNWWWWWWWWWWWWWN0l,'.......''............              ..............                
                        ...............'',::;'';c:col:;coddkXXxdKWWWWWWWWWWWWWWWNXKxc:c:'...,'.......,'....           ............... ..              
                       ............'''..',:c:;,',:::::;llcdOXNXXWNXXWWWWWWWWWWWWNXK0dc:c:'..;'............          ....................              
                    ............'''',,,'';;:doc;:oc:c;;ccldx0KKXXOx0NNWWWWWWWWWNXXX0dlllc:,''........';:;..        .;;,,'''''............             
                    ..........'''',,,;;;,,;coc;;,:l:,;;ldxOO0KKK0kxddONWWWNNNNNX00Oddxddxxlcclc;,,,,,,,,,'.        .:oocc::;;,,''.........            
                     .......'',,,,,;;;;:;,''.',:clolcdk0000KKNNNXK0kocoOXNXKKXXK0OdoxOxdxdl:;:ldxkOOxdoc,.          'odddddollc:,...    ...           
                         ...',;;;;;;:::::;;:;.;:lollc:::;;,,;cldOKNNKOoclkXXKKK0Odlll;,,'..    ..';cx0KOc.          .;odxxxdl:'.                      
           ..    ..        ...',;:::::::;;cccc::c:..            .,cxKNXOdclkk00Odc:,.              .cO0d,..          'looc;'.      ...                
           ..  .';,..         ..,;c::::;'':ccllooc:'.               'dOO0klcxKOxo:,             .':dkxc,.....        .,,.        ...                  
        .......'oxo:,..      ....';cc;;,..,clllddcol:;,,'...       .':lodO0OXN0l;,.       ..,:loxOkdl:'......                      .....              
        .......;xkkdl:,.....   ....'::,...';:cccc:c::c:;:cllc::::;:lodoco0NNNWKc..'cllooodk0KKOxdocc:;,'..'..                   .. ..;;'.             
        .......ckxxocloc::,..    ...':;...';;;;,;;,,:lolc;;;;:::;,cllxdlkXWWWWK:..'oKK00OOO0xoool:;;;;::,'''.. ..               ...';c:'              
       ........oOkxddodol:,...     ...;'..';,,:,..,cc:coc'........,cclkOOXWNWW0,....:ooxxdoc;,;;,'',;:c:,'.......           .....',:lc;.              
      ........'okO0Oxddlc:,....       .. ..;cc;,.,lo;;l:'..'.....;;::cxkkXWNNWO'    .:clxxc...',;:ll:;;,,,'......         ...';:::cll:,..             
    ..........:kkkOOkxddol;'...         ...,c:,:,,;;;:l;..''...',;:;;:dkOKNWWW0'    .c0Oxo:,,,,',:cc:;,','........       ..',:cldddxo:,'.             
  ............lOOOOkxxxdoc;,...         ...''..,'...';,...';,,,,;;::;,ckO0NWWW0'     ,kOl,',,,'',;:clc::;'........       ..',:loooddoc:;'.            
  ...........,xOO00OOkxdocc:'...        ......    .......',,,,,,;,;;,,;dkOXNNW0,     .:o:,;:;'',;::cccc:;'.......        ..,;coodddddocc;.            
 ............:kOO0OO0Okdlcc:,...        .'...... .......,,,,,,,,,;;;,,;okOXNNWK;      .;llc:,'',,;::;;,,''.......       ..':clooolcllllc;.  .         
.............cO0OOkOOOkxdolc:,..        .,. ............'','',,,,,,,,,,lkkKNNNK:       .':;;,;;;:c::c:,'.'......         .';clolc::clllc;'.   .       
............'oO00000OOkkkxo:;,'..        .'.........'....''''',,,,,,,,,:ldOKXNK;        .,:::::::clllc;,''.....         ...',,;:;,,;:cc:,... ..       
............;dxk000000OOOkdl:,''..       .'. ....  ......''''''',,,'''';loxO0Kk'         .;::,;;;:loooc;'.....         ..............',,'...          
...........'lkkO00O000OOkdddl;,'...       ...  ...........''''''''''',,;cdkOxdl.   .     ..,;;;;;:c:::;'..'..       ...,,'....    ....';,'..          
 ..........:kOOkkOO000OOOkollc;''...       ... ...........''''''''''''',:ldxdd:.   .      .,;;;;,;,;,...''.        ..'',;;,''..   ...';:;,'.          
  ........;x0Okddkxddkkkkxdddoc;,''..       ..  ..   ....'''.''''''''''';loodd;    ...    ..'.'..',;:',:'.        ..,:c::c:'.......',;::::;...        
   .....'cdOO0Okkko:cccloddoollc:::'...         .     ...'''.''..'''''',;clldd'   .............'.';ldl;.       ..'',:cooodl:;'....',;;,'',;;,'.       
     ..;dkkO0K0O0KOxxkOOOkxollc:;;;,'..               ....'..'...''''''',:ccoc.   .............'',coc.       ...,;;;::looooc;,'..',,;;:c:;;:;...      
    .'cxOOOKKK0OO000KXXKK0Okdllc;,'',,'..         ...............''''.'',:c:c;.  ............,,;clc'     ...';ccc::ldxkkxoo:,,..';;,;;coc;'......     
    .;llllloddooodxxk000Okxxdolll:,',,,'...        ...............''...',;:cc,   ....''....'';:::'      .';;;:loodkO0OO0OOxl:,'',:::clooc:;'..'.......
      ...........',,;:ccllcllcllollc:;,''.....         .................,;:cc'  .....'''..';;;'.      ..';lodxxddO0KX00Okkkkdlllllllcc:,,;;,,''.......
       ....................''..';:ccloccc:;''.....       ...............',:c;. .....',,',,,'.     .. .',,cdO00OOKKKK000kl::;,'.....                   
        ...............           .'c:..,:cc::;,,'....       ...........,,;:'. .....';:;'.       ....,:cdO000koool::;;,.             ..               
           .......                 ...'.  ...'',;;;,,,,'...     .......',,;c,. ....,;;,.       ......',;cl:,'..   ......              .','...         
           ..                     ..  .,'.       .....''...'...........',;:c,....,;;..    ...'..               .....                  .':xxc'...  ..  
                                 ....  .,;'.             ....',,,''......,cl,..';;..    ..,,,'..            ..''...      ..             .cxxdl:'....  
                                .',,.    .,;,.                ..,;:::cc:;:ll;..''..',,''..''..            ...','...     ....              .';lxdc:;,..
                                 .''.      .,,'..              .';:cldddxkOKd'.',:codol:::;.              ........      ...                  .,coxdolc
                  ....           .''.'.       ..'...            .';cldxdxxxkl'';clloool:'..             .......        ..                     ..;clodx
            ............          .';:c'.   .......'...           ...;::coolc,';,'.....                ...'..         ..             .      ...',;;;:l
         ....''.......             .',:l:.   .........''...             .''.....                   ..........        ..                 .......;lxdlcl
EOF
    echo -e "\e[0m"
    sleep 3
    clear
}

# --------------------------------------
# Eyes Wide Shut: Privacy and Security Suite
# --------------------------------------

# Global Variables
IDUMP_DIR="$HOME/Desktop/Idump"
ENCRYPTED_DIR="$HOME/Desktop/Idump_encrypted"
RAMDISK_DIR="/mnt/ramdisk"
VPN_CONFIG="$IDUMP_DIR/anonymous_vpn.ovpn"
TOR_PROXY="socks5://127.0.0.1:9050"
FIREWALL_RULES="/etc/iptables.rules"
MENU_CHOICE=""
PASSWORD="secure_password"
INTERFACE=$(ip route | grep default | awk '{print $5}' || echo "wlan0")
DISK=$(lsblk -nd --output NAME | head -n 1 || echo "sda")
CHAT_PORT=4444
CHAT_SERVER_PID=""
SCAN_RESULTS="$HOME/ip_scan_results.txt"
CHAT_ROOMS_LIST="$HOME/discovered_chat_rooms.txt"
PRIVATE_RANGES=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
)

# Ensure Required Directories
mkdir -p $IDUMP_DIR $ENCRYPTED_DIR $RAMDISK_DIR

# --------------------------------------
# Core Functions
# --------------------------------------

# Install Dependencies
install_dependencies() {
    echo "Installing required tools and dependencies..."
    sudo apt update
    sudo apt install -y openvpn tor proxychains macchanger iptables openssl curl \
                        cron lynis clamav socat telnet gnome-terminal xterm
    echo "Dependencies installed successfully."
}

# Verify Dependencies Are Installed
check_dependencies() {
    local missing=()
    local deps=(openvpn tor proxychains macchanger iptables openssl curl \
                cron lynis clamscan socat telnet gnome-terminal xterm)

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if (( ${#missing[@]} )); then
        echo "Missing dependencies: ${missing[*]}"
        echo "Select option 1 from the main menu to install them."
        return 1
    else
        echo "All dependencies are present."
    fi
}

# --------------------------------------
# Eyes Wide Shut: IPv4 Scanner and Privacy Suite
# --------------------------------------

# Global Variables
LOG_FILE="$HOME/scan_log.txt"
COMMON_RANGES=(
    "1.1.1.0-1.1.1.255"     # Cloudflare DNS
    "8.8.8.0-8.8.8.255"     # Google DNS
    "185.199.108.0-185.199.111.255" # GitHub IPs
    "13.224.0.0-13.224.255.255"    # AWS CloudFront
    "23.235.32.0-23.235.39.255"    # Fastly CDN
    "151.101.0.0-151.101.255.255"  # Fastly CDN
    "104.16.0.0-104.31.255.255"    # Cloudflare
    "34.192.0.0-34.255.255.255"    # AWS EC2
)

# Ensure Logs and Results Files Exist
touch $SCAN_RESULTS
touch $LOG_FILE

# --------------------------------------
# Utility Functions
# --------------------------------------

# Convert IP Range to CIDR Notation
range_to_cidr() {
    local start_ip="$1"
    local end_ip="$2"

    # Validate the input IPs
    if [[ ! "$start_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ ! "$end_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo ""
        return
    fi

    # Helper to convert IP to integer
    ip_to_int() {
        local IFS=.
        read -r a b c d <<< "$1"
        echo $(( (a<<24) | (b<<16) | (c<<8) | d ))
    }

    # Helper to convert integer back to IP
    int_to_ip() {
        local ip=$1
        printf "%d.%d.%d.%d" \
            $(( (ip>>24) & 255 )) \
            $(( (ip>>16) & 255 )) \
            $(( (ip>>8) & 255 )) \
            $(( ip & 255 ))
    }

    local start=$(ip_to_int "$start_ip")
    local end=$(ip_to_int "$end_ip")
    local cidrs=()

    while (( start <= end )); do
        local max=32
        while (( max > 0 )); do
            local mask=$(( 0xffffffff << (32 - (max - 1)) & 0xffffffff ))
            if (( (start & mask) != start )); then
                break
            fi
            local last=$(( start + (1 << (32 - (max - 1))) - 1 ))
            if (( last > end )); then
                break
            fi
            max=$(( max - 1 ))
        done
        local prefix=$(( max ))
        cidrs+=( "$(int_to_ip $start)/$prefix" )
        start=$(( start + (1 << (32 - prefix)) ))
    done

    echo "${cidrs[*]}"
}

# Scan Selected IP Range
scan_ips() {
    local range="$1"
    echo "Scanning range: $range..."

    # Extract start and end IPs
    local start_ip=$(echo $range | cut -d '-' -f 1)
    local end_ip=$(echo $range | cut -d '-' -f 2)

    # Convert range to CIDR blocks
    local cidr_blocks
    cidr_blocks=$(range_to_cidr "$start_ip" "$end_ip")

    if [[ -z "$cidr_blocks" ]]; then
        echo "Error: Unable to format range $range. Skipping."
        return
    fi

    # Scan each CIDR block
    for cidr in $cidr_blocks; do
        echo "Scanning CIDR block: $cidr..."
        nmap -p 4444 "$cidr" --open -oG - | awk '/Up$/{print $2}' >> $SCAN_RESULTS
    done

    if [ -s $SCAN_RESULTS ]; then
        echo "Active IPs found in range $range. Results saved to $SCAN_RESULTS."
        echo "$(date): Scanned $range - Results found." >> $LOG_FILE
    else
        echo "No active IPs found in range $range."
        echo "$(date): Scanned $range - No results." >> $LOG_FILE
    fi
}

# Automatic Scanning of All Ranges
automatic_scanning() {
    echo "Starting automatic scanning of all pre-defined ranges..."
    for range in "${COMMON_RANGES[@]}"; do
        # Extract start and end IPs from the range
        local start_ip=$(echo $range | cut -d '-' -f 1)
        local end_ip=$(echo $range | cut -d '-' -f 2)

        # Convert the range to CIDR
        local cidr_blocks
        cidr_blocks=$(range_to_cidr "$start_ip" "$end_ip")

        if [[ -z "$cidr_blocks" ]]; then
            echo "Error: Unable to format range $range. Skipping."
            continue
        fi

        # Scan CIDR blocks
        for cidr in $cidr_blocks; do
            echo "Scanning CIDR block: $cidr..."
            nmap -p 4444 "$cidr" --open -oG - | awk '/Up$/{print $2}' >> $SCAN_RESULTS
        done
    done

    if [ -s $SCAN_RESULTS ]; then
        echo "Automatic scanning complete. Active IPs saved to $SCAN_RESULTS."
    else
        echo "No active IPs found during automatic scanning."
    fi
}

# Ping IPs and Send Chat Invitation
ping_and_invite_ips() {
    local ip_file="$SCAN_RESULTS"

    # Ensure the results file exists and is not empty
    if [[ ! -s "$ip_file" ]]; then
        echo "No IPs found in $ip_file. Ensure scanning has been done."
        return
    fi

    echo "Pinging IPs and sending invitations..."

    # Loop through each IP in the results file
    while IFS= read -r ip; do
        # Validate the IP format
        if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "Skipping invalid IP: $ip"
            continue
        fi

        # Ping the IP to check if it's reachable
        if ping -c 1 -W 1 "$ip" > /dev/null 2>&1; then
            echo "IP $ip is reachable. Sending invitation..."

            # Use a random port for the listener to avoid conflicts
            local random_port=$((RANDOM % 10000 + 1024))

            # Start a `socat` listener in the background with a timeout
            socat TCP-LISTEN:$random_port,reuseaddr,fork - > /tmp/socat_response_$random_port &
            local socat_pid=$!

            # Send an invitation using `socat` (port 4444 assumed open on the remote side)
            echo -e "REQUEST TO JOIN CHAT ROOM\nType 'Y' to join or 'N' to decline." | socat - TCP:$ip:4444

            # Wait for a response (3-minute timeout)
            sleep 180

            # Read the response from the temporary file
            if [ -f /tmp/socat_response_$random_port ]; then
                local response=$(cat /tmp/socat_response_$random_port | tr -d '\r\n')
                rm -f /tmp/socat_response_$random_port

                if [[ "$response" == "Y" || "$response" == "y" ]]; then
                    echo "User at $ip accepted the invitation."

                    # Ask for their nickname
                    echo "Waiting for nickname from $ip..."
                    socat TCP-LISTEN:$random_port,reuseaddr,fork - > /tmp/nickname_response_$random_port &
                    sleep 60
                    if [ -f /tmp/nickname_response_$random_port ]; then
                        local nickname=$(cat /tmp/nickname_response_$random_port | tr -d '\r\n')
                        rm -f /tmp/nickname_response_$random_port
                        [ -z "$nickname" ] && nickname="Guest"
                        echo "Starting chat session with $nickname at $ip..."
                        start_chat_session "$ip" "$nickname"
                    else
                        echo "No nickname received. Starting chat with default settings."
                        start_chat_session "$ip" "Guest"
                    fi
                else
                    echo "No response or user at $ip declined the invitation."
                fi
            else
                echo "No response received from $ip within timeout."
            fi

            # Terminate the listener
            kill $socat_pid 2>/dev/null
        else
            echo "IP $ip is unreachable. Skipping..."
        fi
    done < "$ip_file"

    echo "Finished pinging and inviting IPs."
}



exclude_private_ranges() {
    if [[ ! -s "$SCAN_RESULTS" ]]; then
        echo "No scan results to filter."
        return
    fi

    echo "Removing private IP addresses from $SCAN_RESULTS..."
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)" "$SCAN_RESULTS" > "${SCAN_RESULTS}.tmp"
    mv "${SCAN_RESULTS}.tmp" "$SCAN_RESULTS"
    echo "Private IPs removed."
}

# Start Chat Session
start_chat_session() {
    local ip="$1"
    local nickname="$2"

    # Open a chat window with the user
    CHAT_CMD="socat - TCP:$ip:4444 | tee >(sed \"s/^/[$nickname] /g\")"
    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -c "$CHAT_CMD"
    elif command -v xterm >/dev/null 2>&1; then
        xterm -fa 'Monospace' -fs 10 -bg black -fg white -e bash -c "$CHAT_CMD" &
    else
        echo "No compatible terminal emulator found! Please install gnome-terminal or xterm."
    fi
}


# --------------------------------------
# Listener For Notifications
# --------------------------------------
listen_for_responses() {
    echo "Listening for incoming responses..."
    socat TCP-LISTEN:5555,reuseaddr,fork | while read -r response; do
        ip=$(echo "$response" | awk '{print $1}')
        message=$(echo "$response" | cut -d' ' -f2-)

        # Show the notification
        if command -v notify-send &>/dev/null; then
            notify-send "Response from $ip" "$message"
        else
            echo "Notification: $message from $ip"
        fi

        # Open chat if user agrees
        if [[ "$message" =~ ^yes$ ]]; then
            echo "User at $ip accepted the chat request."
            initiate_chat "$ip"
        else
            echo "User at $ip declined the chat request."
        fi
    done
}

# --------------------------------------
# Initiate Chat
# --------------------------------------
initiate_chat() {
    local ip="$1"
    echo "Starting chat session with $ip..."
    read -p "Enter your nickname: " NICKNAME
    [ -z "$NICKNAME" ] && NICKNAME="Anonymous"

    # Open a chat window with the user
    CHAT_CMD="socat - TCP:$ip:4444 | tee >(sed \"s/^/[$NICKNAME] /g\")"
    if command -v gnome-terminal &>/dev/null; then
        gnome-terminal -- bash -c "$CHAT_CMD"
    elif command -v xterm &>/dev/null; then
        xterm -fa 'Monospace' -fs 10 -bg black -fg white -e bash -c "$CHAT_CMD" &
    else
        echo "No compatible terminal emulator found! Please install gnome-terminal or xterm."
    fi
}

# --------------------------------------
# IPv4 Scanner Submenu
# --------------------------------------

ipv4_scanner_menu() {
    while true; do
        echo "---------------------------------"
        echo "   IPv4 Scanner - Submenu"
        echo "---------------------------------"
        echo "1. Select and Scan an IP Range"
        echo "2. Automatic Scanning (All Ranges)"
        echo "3. Exclude Private IP Ranges"
        echo "4. Send Join Requests to Active IPs"
        echo "5. View Scan Logs"
        echo "6. Back to Main Menu"
        echo "---------------------------------"
        read -p "Choose an option: " SCAN_CHOICE
        case $SCAN_CHOICE in
            1)
                echo "Enter the range in the format: start_ip-end_ip (e.g., 192.0.2.0-192.0.2.255)"
                read -p "Enter IP range to scan: " RANGE
                scan_ips "$RANGE"
                ;;
            2)
                automatic_scanning
                ;;
            3)
                exclude_private_ranges
                ;;
            4)
                ping_and_invite_ips
                ;;
            5)
                echo "Displaying scan logs..."
                cat $LOG_FILE
                ;;
            6)
                return
                ;;
            *)
                echo "Invalid option. Try again."
                ;;
        esac
    done
}

# Start Public Chat Server
start_public_chat_server() {
    echo "Starting public chat server on port $CHAT_PORT..."
    socat tcp-listen:$CHAT_PORT,reuseaddr,fork exec:'/bin/cat' &
    CHAT_SERVER_PID=$!
    echo "Public chat server started with PID $CHAT_SERVER_PID."
}

# Start Private Chat Server
start_private_chat_server() {
    read -s -p "Set chat server password: " CHAT_PASSWORD
    echo
    export CHAT_PASSWORD
    echo "Starting private chat server on port $CHAT_PORT..."
    socat tcp-listen:$CHAT_PORT,reuseaddr,fork SYSTEM:"$PWD/private_chat_handler.sh" &
    CHAT_SERVER_PID=$!
    echo "Private chat server started with PID $CHAT_SERVER_PID."
}

# Chat Server Menu
start_chat_server() {
    echo "1. Start Public Chat Server"
    echo "2. Start Private Chat Server"
    read -p "Choose server type: " type
    case $type in
        1) start_public_chat_server ;;
        2) start_private_chat_server ;;
        *) echo "Invalid choice." ;;
    esac
}

# Enter Chat Room with Nickname
open_chat_client() {
    read -p "Enter your nickname: " NICKNAME
    read -p "Enter the IP address of the chat room [127.0.0.1]: " CHAT_IP
    CHAT_IP=${CHAT_IP:-127.0.0.1}
    echo "Connecting to the chat room at $CHAT_IP as $NICKNAME..."

    HANDSHAKE=$(timeout 2 nc $CHAT_IP $CHAT_PORT 2>/dev/null | head -n 1 | tr -d '\r')
    if [[ "$HANDSHAKE" == "PASSWORD_REQUIRED" ]]; then
        read -s -p "Enter chat room password: " CHAT_PASSWORD
        echo
        COMMAND="(echo \"$CHAT_PASSWORD\"; cat) | nc $CHAT_IP $CHAT_PORT | tee >(sed \"s/^/[$NICKNAME] /g\")"
    else
        COMMAND="nc $CHAT_IP $CHAT_PORT | tee >(sed \"s/^/[$NICKNAME] /g\")"
    fi

    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -c "echo -e '\033]10;#FFFFFF\007\033]11;#000000\007'; $COMMAND"
    elif command -v xterm >/dev/null 2>&1; then
        xterm -fa 'Monospace' -fs 10 -bg black -fg white -e bash -c "$COMMAND" &
    else
        echo "No compatible terminal emulator found! Please install gnome-terminal or xterm."
    fi
}

# Join Another Chat Room
join_custom_chat_room() {
    read -p "Enter the IP address of the chat room: " CHAT_IP
    read -p "Enter the port of the chat room: " CHAT_PORT
    read -p "Enter your nickname: " NICKNAME
    echo "Connecting to chat room at $CHAT_IP:$CHAT_PORT as $NICKNAME..."

    HANDSHAKE=$(timeout 2 nc $CHAT_IP $CHAT_PORT 2>/dev/null | head -n 1 | tr -d '\r')
    if [[ "$HANDSHAKE" == "PASSWORD_REQUIRED" ]]; then
        read -s -p "Enter chat room password: " CHAT_PASSWORD
        echo
        COMMAND="(echo \"$CHAT_PASSWORD\"; cat) | nc $CHAT_IP $CHAT_PORT | tee >(sed \"s/^/[$NICKNAME] /g\")"
    else
        COMMAND="nc $CHAT_IP $CHAT_PORT | tee >(sed \"s/^/[$NICKNAME] /g\")"
    fi

    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -c "echo -e '\033]10;#FFFFFF\007\033]11;#000000\007'; $COMMAND"
    elif command -v xterm >/dev/null 2>&1; then
        xterm -fa 'Monospace' -fs 10 -bg black -fg white -e bash -c "$COMMAND" &
    else
        echo "No compatible terminal emulator found! Please install gnome-terminal or xterm."
    fi
}

# Discover Chat Rooms on Local Network
discover_chat_rooms() {
    read -p "Enter the first three octets of the IP range (e.g., 192.168.1): " BASE
    : > "$CHAT_ROOMS_LIST"
    for i in $(seq 1 254); do
        ip="$BASE.$i"
        HANDSHAKE=$(timeout 1 nc "$ip" "$CHAT_PORT" 2>/dev/null | head -n 1 | tr -d '\r')
        if [[ "$HANDSHAKE" == "PASSWORD_REQUIRED" ]]; then
            echo "$ip PRIVATE" | tee -a "$CHAT_ROOMS_LIST"
        elif nc -z -w1 "$ip" "$CHAT_PORT" 2>/dev/null; then
            echo "$ip PUBLIC" | tee -a "$CHAT_ROOMS_LIST"
        fi
    done
    echo "Discovery complete. Results saved to $CHAT_ROOMS_LIST"
}

# Stop Chat Server
stop_chat_server() {
    if [ -n "$CHAT_SERVER_PID" ]; then
        echo "Stopping the chat server..."
        kill $CHAT_SERVER_PID
        echo "Chat server stopped."
    else
        echo "Chat server is not running."
    fi
}

# Install Tor Browser
install_tor_browser() {
    echo "Downloading and installing the Tor Browser..."
    cd $HOME
    curl -s https://www.torproject.org/dist/torbrowser/ | grep -oP '(?<=href=")[^"]*linux[^"]*' | head -1 | wget -i -
    tar -xvf tor-browser-linux*.tar.xz
    mv tor-browser_* tor-browser
    echo "Tor Browser installed in $HOME/tor-browser."
}

# Configure RAM Disk for Ephemeral Data
setup_ramdisk() {
    echo "Configuring RAM disk for temporary data..."
    if mountpoint -q "$RAMDISK_DIR"; then
        echo "RAM disk already mounted at $RAMDISK_DIR."
    else
        sudo mount -t tmpfs -o size=2G tmpfs "$RAMDISK_DIR" || { echo "Failed to configure RAM disk"; exit 1; }
        echo "RAM disk mounted at $RAMDISK_DIR."
    fi
}

# Rotate MAC Address
rotate_mac() {
    echo "Rotating MAC address..."
    sudo ifconfig $INTERFACE down || echo "Failed to bring down interface $INTERFACE."
    sudo macchanger -r $INTERFACE || echo "Failed to randomize MAC address."
    sudo ifconfig $INTERFACE up || echo "Failed to bring up interface $INTERFACE."
    macchanger -s $INTERFACE || echo "MAC address verification failed."
}

# Rotate Browser Fingerprint
rotate_browser_fingerprint() {
    echo "Generating random browser fingerprint..."
    BROWSER_AGENT=$(shuf -n 1 <<EOF
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1
EOF
)
    echo "New Browser Agent: $BROWSER_AGENT"
    echo $BROWSER_AGENT > "$RAMDISK_DIR/browser_agent.txt" || echo "Failed to write browser agent."
}

# Configure Firewall for Privacy
setup_firewall() {
    echo "Configuring firewall rules for strict privacy..."
    sudo iptables -F
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 9050 -j ACCEPT
    sudo iptables -A OUTPUT -m owner --uid-owner $(id -u) -j ACCEPT
    sudo iptables -P OUTPUT DROP
    sudo iptables-save > $FIREWALL_RULES
    echo "Firewall rules applied."
}

# Configure and Start Tor
setup_tor() {
    echo "Starting Tor and routing traffic through it..."
    sudo systemctl start tor
    export http_proxy=$TOR_PROXY
    export https_proxy=$TOR_PROXY
    export ftp_proxy=$TOR_PROXY
    echo "Tor proxy applied for all traffic."
}

# Configure VPN
generate_vpn_config() {
    echo "Generating OpenVPN configuration..."
    cat <<EOF > $VPN_CONFIG
client
dev tun
proto udp
remote vpnbook.com 53
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3
redirect-gateway def1
block-outside-dns
<ca>
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7m8Mw8oBoVUm5cF6sGMa
-----END CERTIFICATE-----
</ca>
EOF
    echo "VPN configuration created at $VPN_CONFIG."
}

# Start VPN
start_vpn() {
    echo "Starting VPN..."
    [ -f "$VPN_CONFIG" ] || generate_vpn_config
    sudo killall openvpn 2>/dev/null
    sudo openvpn --config "$VPN_CONFIG" --daemon || { echo "Failed to start VPN"; exit 1; }
    sleep 10
    curl -s ifconfig.me || echo "Failed to retrieve public IP."
}

# Scan for Malware/Keyloggers
scan_for_threats() {
    echo "Scanning for malware and keyloggers..."
    sudo lynis audit system > "$RAMDISK_DIR/lynis_report.txt"
    echo "Lynis system audit report saved to: $RAMDISK_DIR/lynis_report.txt"

    sudo clamscan -r / > "$RAMDISK_DIR/clamav_report.txt"
    echo "ClamAV malware scan report saved to: $RAMDISK_DIR/clamav_report.txt"
}

# Encrypt Data
encrypt_data() {
    echo "Encrypting data in $IDUMP_DIR..."
    for file in "$IDUMP_DIR"/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            openssl enc -aes-256-cbc -salt -in "$file" -out "$ENCRYPTED_DIR/${filename}.enc" -k "$PASSWORD"
            echo "Encrypted $filename to ${filename}.enc"
        fi
    done
    echo "All files encrypted and saved to $ENCRYPTED_DIR."
}

# Revert to Original Settings
revert_to_original() {
    echo "Reverting to original settings..."
    echo "Removing dependencies..."
    sudo apt remove --purge -y openvpn tor proxychains macchanger iptables openssl curl \
                          cron lynis clamav socat telnet gnome-terminal xterm
    echo "Dependencies removed."
    echo "Flushing iptables rules..."
    sudo iptables -F
    sudo iptables -P OUTPUT ACCEPT
    echo "Unmounting RAM disk..."
    sudo umount $RAMDISK_DIR || echo "RAM disk not mounted or already unmounted."
    echo "Clearing configurations..."
    rm -rf $IDUMP_DIR $ENCRYPTED_DIR $RAMDISK_DIR
    echo "System reverted to original state."
}

main_menu() {
    while true; do
        echo "---------------------------------"
        echo "   Eyes Wide Shut - Main Menu"
        echo "---------------------------------"
        echo "1. Install Dependencies"
        echo "2. Install Tor Browser"
        echo "3. Configure RAM Disk"
        echo "4. Rotate MAC Address"
        echo "5. Rotate Browser Fingerprint"
        echo "6. Setup Firewall and Tor"
        echo "7. Start VPN"
        echo "8. Scan for Malware/Keyloggers"
        echo "9. Encrypt Data"
        echo "10. Discover Chat Rooms"
        echo "11. Enter Chat Room"
        echo "12. Join Another Chat Room"
        echo "13. Start Chat Server"
        echo "14. Revert to Original Settings"
        echo "15. IPv4 Scanner"
        echo "16. Check Dependencies"
        echo "17. Exit"
        echo "---------------------------------"
        read -p "Choose an option: " MENU_CHOICE
        case $MENU_CHOICE in
            1) install_dependencies ;;
            2) install_tor_browser ;;
            3) setup_ramdisk ;;
            4) rotate_mac ;;
            5) rotate_browser_fingerprint ;;
            6) setup_firewall; setup_tor ;;
            7) start_vpn ;;
            8) scan_for_threats ;;
            9) encrypt_data ;;
            10) discover_chat_rooms ;;
            11) open_chat_client ;;
            12) join_custom_chat_room ;;
            13) start_chat_server ;;
            14) revert_to_original ;;
            15) ipv4_scanner_menu ;;
            16) check_dependencies ;;
            17) echo "Exiting. Stay anonymous!"; exit 0 ;;
            *) echo "Invalid option. Try again." ;;
        esac
    done
}

# --------------------------------------
# Start Script
# --------------------------------------

display_venetian_mask
main_menu
