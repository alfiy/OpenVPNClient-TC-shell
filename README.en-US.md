

# Introduction to OpenVPN Client tc Throttling Script

This script is a traffic control daemon for OpenVPN environments, designed to dynamically manage network bandwidth for connected users. It periodically parses status logs to identify online users and utilizes Linux's Traffic Control (tc) tools and HTB queue rules to assign specific rate-limiting policies to each client. The script supports defining personalized upload/download bandwidth for users or roles via configuration files, and leverages IFB devices for precise interception of bidirectional traffic. To ensure system robustness, it features idempotent initialization and automatic state recovery, automatically rebuilding in-memory IP mappings after service restarts. Through this fully automated monitoring and execution mechanism, administrators can efficiently implement on-demand bandwidth allocation within the virtual private network.


## Throttling Principles:
Upload Throttling: Sets HTB rules directly on the outbound traffic of tun0 (matching dst_ip to the client).
Download Throttling: Redirects the inbound traffic of tun0 to the outbound interface of the ifb0 virtual NIC, then sets HTB rules on ifb0's outbound traffic (matching src_ip to the client).
Idempotent Design: All tc rule creations/deletions check for existence first to avoid errors from duplicate operations, ensuring the script can be restarted repeatedly.
Dynamic Operation: Checks client status every 3 seconds, automatically creating rate-limiting rules for new clients and cleaning up rules for offline clients. Supports differentiated bandwidth configuration at the user/role level.
## Core Files / Configuration
status.log: OpenVPN status log, serving as the data source for client status.
tc-users.conf: User/role bandwidth configuration (Format: Username/RoleName=Upload_Bandwidth Download_Bandwidth).
tc-roles.map: User-to-role mapping (Format: Username=RoleName).
tun0/ifb0: Core network interfaces, used respectively for upload/download throttling.
## Runtime Dependencies
The kernel must load the ifb module (modprobe ifb).
The system must have iproute2 installed (provides tc/ip commands).
OpenVPN must have status logging enabled (add `status /var/log/openvpn/status.log` to the configuration file).


## How does this script dynamically manage OpenVPN client network bandwidth limits through automation?
This script achieves dynamic automated management of client bandwidth by combining Linux's Traffic Control (TC) tools, Intermediate Functional Block (IFB) devices, and real-time monitoring of OpenVPN status logs. Its core logic can be summarized in the following key dimensions:
1. Initialization of Traffic Control Infrastructure
Upon script startup, the init_tc function is responsible for building the network environment required for throttling:
• Traffic Redirection: Due to the limited functionality of Linux TC in handling ingress traffic, the script loads the ifb module and creates the ifb0 device. It redirects all inbound traffic from the VPN device (tun0) to the outbound direction of ifb0, thereby enabling control over download bandwidth.
• Hierarchical Token Bucket (HTB) Queues: HTB queue rules (qdisc) are established on tun0 and ifb0 respectively. This hierarchical structure allows the script to create independent classes for each client and assign specific bandwidth caps.
2. Dynamic Monitoring and Identity Recognition
The script tracks client changes via an infinite loop (executing every 3 seconds):
• Status Parsing: The parse_clients function reads the OpenVPN status.log file, extracting the IP addresses and usernames of currently online clients by parsing the "ROUTING TABLE" section.
• Configuration Retrieval: The get_user_rate function dynamically looks up rate-limiting policies based on the username. It first checks the user-specific configuration file (tc-users.conf); if not found, it checks the role mapping (tc-roles.map); if neither is found, it applies a default 2Mbit bandwidth limit.
3. Automated Management of Client Lifecycle
The script automatically handles client connections and disconnections by maintaining an in-memory mapping table (IP_CLASS_MAP):
• Automatic Allocation and Throttling (Add Client): When a new IP connection is detected, add_client allocates a unique ClassID from a preset pool (101-350). It then executes tc class add to create bandwidth limits and uses tc filter add (based on flower filters and IP addresses) to associate the specific client's traffic with the limit class.
• Automatic Cleanup (Del Client): When a client no longer appears in status.log, the script calls del_client to automatically remove the corresponding TC filters and classes, releasing the ClassID for future use to prevent system resource waste.
4. Robustness and State Recovery
To ensure the reliability of the automation process, the script features the following:
• State Rebuilding: If the script restarts, the rebuild_state function scans existing TC rules in the kernel and reconstructs the in-memory IP-to-ClassID mapping alongside status.log, avoiding conflicts with active connections.
• Idempotent Operations: Before executing creation operations, the script checks if rules already exist via class_exists and filter_exists, preventing errors from duplicate additions.
• Username Change Detection: If the username associated with the same IP changes, the script first deletes the old rules and recreates the throttling policy based on the new user's permissions.

## What key mechanisms does the script employ to ensure the initialization and state recovery of traffic control rules?

The script ensures the stability and consistency of traffic control rules during startup and runtime through a complete initialization process, kernel state scanning mechanism, and idempotency checks. The key mechanisms employed are as follows:
1. Standardized Initialization of Traffic Control (TC) Rules
Within the init_tc function, the script executes a series of steps to build the basic throttling environment:
• Dependency and Device Checks: The script first verifies the existence of the tc, ip, and modprobe commands, and attempts to load the ifb kernel module.
• Delayed Waiting Mechanism: Considering that device creation may lag during OpenVPN startup, the script loops for up to 30 seconds until the tun0 device appears in the system.
• Forced Cleanup of Residuals: To ensure a clean environment, the script first deletes the root and ingress queues on tun0, and completely removes and recreates the ifb0 device to eliminate stale rules left from previous runs.
• Hierarchical Architecture Setup: HTB (Hierarchical Token Bucket) root queues are established on tun0 (controlling uploads) and ifb0 (controlling downloads) respectively, along with default classes and traffic redirection filters.
2. Deep Kernel State Recovery (Rebuild State)
To avoid interfering with existing connections and recover management state after a script restart, the rebuild_state function implements the following:
• Real-time Kernel Scanning: The script extracts existing filter rules from the kernel by parsing the output of the tc filter show command.
• Bidirectional Data Extraction: Scans dst_ip (destination IP) on tun0 and src_ip (source IP) on ifb0, accurately capturing their corresponding flowids (i.e., ClassIDs).
• User Relationship Sync: The script reads the OpenVPN status.log file, associates the extracted IP addresses with current usernames, and reconstructs the in-memory IP_CLASS_MAP mapping table.
• Resource Occupation Marking: During recovery, discovered ClassIDs are marked in the CLASSID_USED array to prevent new connections from being assigned active ClassIDs.
3. Idempotency and Robustness of Operations
The script adopts a "check first, operate later" strategy when performing add/delete operations to ensure system robustness:
• Existence Validation: Helper functions like class_exists, filter_exists_dst, and filter_exists_src confirm whether a rule already exists in the kernel before adding it, avoiding errors from duplicate creation.
• Error Retry Logic: When the main loop starts, if init_tc initialization fails, the script supports up to 5 retries with a 5-second interval, handling temporary system resource contention or unready network devices.
• Silent Handling: When deleting rules (del_client), the script ignores non-existent items, ensuring unnecessary error logs are not triggered during frequent client connections/disconnections or system fluctuations.

## How to set custom bandwidth limits for specific users in the configuration files?
Based on the script's design logic, you can set custom bandwidth limits for specific users by editing two main configuration files. The script supports both direct username-based settings and bulk role-based settings.
Specific operation steps are as follows:
1. Configuration File Paths and Formats
The script defines relevant configuration file paths in its initialization section:
• User Throttling Config: /etc/openvpn/tc-users.conf
• User-Role Mapping: /etc/openvpn/tc-roles.map
2. Method 1: Directly for Specific Users
You can directly define settings in /etc/openvpn/tc-users.conf following the format Username=Upload_Bandwidth Download_Bandwidth.
• Operation Steps: Open /etc/openvpn/tc-users.conf and add content similar to the following:
• Script Logic: The get_user_rate function prioritizes searching this file. If it matches the currently logged-in username, it directly extracts the corresponding upload and download rates.
3. Method 2: Associative Setting via Roles
If you have a large number of users requiring the same throttling policy, you can use the role mapping feature. This requires editing two files simultaneously:
1. Define Role Limits: Define the bandwidth for roles in /etc/openvpn/tc-users.conf.
2. Establish User-to-Role Mapping: Point usernames to specific roles in /etc/openvpn/tc-roles.map.
• Script Logic: If a direct username match is not found in tc-users.conf, the script looks up the user's role in tc-roles.map, then returns to tc-users.conf to fetch the rate limit based on the role name.
4. Default Rate Limit Notes
If no corresponding configuration is found in the above two files, the script will apply preset default limits:
• Default Upload: 2Mbit
• Default Download: 2Mbit
Notes
• Bandwidth Units: Use units supported by Linux TC when setting, such as Mbit, Kbit, bps, etc.
• Format Requirements: Each line must strictly follow the key=value format without spaces, as the script uses cut -d= -f2 to parse data.
• Effective Time: The script's main loop checks status.log every 3 seconds. Configurations take effect immediately for newly connected users. For already online users, if a username change is detected, the script automatically rebuilds their corresponding traffic control class to apply the new policy.

## Does the ClassID range from 101 to 350 set in the script limit the maximum number of concurrent users?
Yes, the ClassID range from 101 to 350 set in the script does limit the maximum number of concurrent users that the script can dynamically manage bandwidth for simultaneously.
Detailed analysis is as follows:
1. Calculation of Concurrent Users
Based on the script's basic configuration, CLASSID_START is set to 101, and CLASSID_END is set to 350. This means the script reserves a resource pool containing 250 unique identifiers (ClassIDs) (350−101+1=250).
2. Correspondence between ClassID and Users
• Unique Allocation: In the add_client logic, whenever a client with a new IP connects, the script calls the alloc_classid function to allocate an unoccupied ClassID from this pool.
• One-to-One Binding: This ClassID is used simultaneously for traffic control classes on tun0 (upload) and ifb0 (download), and is bound to the user's IP address.
• Memory Recording: Successfully allocated ClassIDs are recorded in the CLASSID_USED array and the IP_CLASS_MAP mapping table.
3. Behavior Upon Reaching the Limit
When all 250 IDs in the pool are occupied and no users disconnect to free them:
• The alloc_classid function will return an error after iterating through all values from 101 to 350, as it cannot find a free ID.
• The script will output a log error: "❌ classid pool exhausted".
• For concurrent users beyond the 250th, the script will be unable to create rate-limiting rules for them (skipping the add_client logic), meaning these users may be unthrottled or follow the system's default queue rules.
4. Resource Reclamation and Reuse
This limit applies only to the number of simultaneously online users. When a client disconnects, the script calls free_classid via the del_client process to remove the ID from CLASSID_USED, making it available for reuse by subsequently connecting users.
Summary: The script currently supports bandwidth management for a maximum of 250 concurrent users. If your OpenVPN server needs to support more simultaneous users, you must manually modify the CLASSID_END parameter at the beginning of the script to expand the resource pool.

## Creating a systemd Service

Save the vpn-tc-daemon.service file in the /etc/systemd/system directory, then execute the following commands:

```bash
systemctl daemon-reload
systemctl enable vpn-tc-daemon.service
systemctl start vpn-tc-daemon.service
```
