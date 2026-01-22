#!/usr/bin/env bash
set -euo pipefail

#####################################
# 基本配置
#####################################
STATUS_LOG="/var/log/openvpn/status.log"
LOG_FILE="/var/log/openvpn/vpn-tc-daemon.log"

VPN_DEV="tun0"
IFB_DEV="ifb0"

CLASSID_START=101
CLASSID_END=350

DEFAULT_UP="2Mbit"
DEFAULT_DOWN="2Mbit"

USER_RATE_CONF="/etc/openvpn/tc-users.conf"
USER_ROLE_MAP="/etc/openvpn/tc-roles.map"

INTERVAL=3

# 显式以全局方式声明（避免函数内 declare 导致局部/未绑定问题）
declare -g -A IP_CLASS_MAP=()    # ip -> "user:classid"
declare -g -A CLASSID_USED=()    # classid -> 1
declare -g -A LAST_SEEN=()    # ip -> user
REPAIR_TICK=0
REPAIR_INTERVAL=5            # 每 5 轮才允许一次 repair

#####################################
# 工具函数
#####################################
log() {
    echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

get_user_rate() {
    local user="$1"

    if [[ -f "$USER_RATE_CONF" ]] && grep -q "^${user}=" "$USER_RATE_CONF"; then
        grep "^${user}=" "$USER_RATE_CONF" | head -n1 | cut -d= -f2
        return
    fi

    if [[ -f "$USER_ROLE_MAP" ]]; then
        local role
        role=$(grep "^${user}=" "$USER_ROLE_MAP" | head -n1 | cut -d= -f2)
        if [[ -n "$role" ]] && grep -q "^${role}=" "$USER_RATE_CONF"; then
            grep "^${role}=" "$USER_RATE_CONF" | head -n1 | cut -d= -f2
            return
        fi
    fi

    echo "${DEFAULT_UP} ${DEFAULT_DOWN}"
}


#####################################
# 辅助：检查 tc class/filter 存在性（用于幂等）
#####################################
class_exists() {
    local dev="$1"
    local prefix="$2"   # "1:" or "2:"
    local classid="$3"
    if tc class show dev "$dev" 2>/dev/null | grep -q -E "${prefix}${classid}\b"; then
        return 0
    fi
    return 1
}

filter_exists_dst() {
    local dev="$1" parent="$2" ip="$3"

    if tc filter show dev "$dev" parent "$parent" 2>/dev/null | grep -qw "dst_ip $ip"; then
        return 0
    fi
    return 1
}

filter_exists_src() {
    local dev="$1"
    local parent="$2"
    local ip="$3"
    if tc filter show dev "$dev" parent "$parent" 2>/dev/null | grep -qw "src_ip $ip"; then
        return 0
    fi
    return 1
}


#####################################
# TC 初始化（尽量幂等）
#####################################
init_tc() {
    log "开始初始化 TC 规则..."

    # 检查必要命令
    for c in tc ip modprobe; do
        if ! cmd_exists "$c"; then
            log "❌ 需要命令缺失: $c"
            return 1
        fi
    done

    # 加载 ifb 模块
    if ! lsmod | grep -q "^ifb\b"; then
        if ! modprobe ifb 2>/dev/null; then
            log "⚠️ 无法加载 ifb 模块（继续尝试）"
        fi
    fi

    local wait_count=0
    while [[ ! -d "/sys/class/net/$VPN_DEV" ]] && [[ $wait_count -lt 30 ]]; do
        log "⏳ 等待 $VPN_DEV 设备就绪... ($wait_count/30)"
        sleep 1
        ((wait_count++))
    done
    [[ ! -d "/sys/class/net/$VPN_DEV" ]] && { log "❌ $VPN_DEV 不存在"; return 1; }

    log "🧹 清理可能的残留 ingress/filter（不会删除所有东西，仅确保可重复创建）"
    tc qdisc del dev "$VPN_DEV" root 2>/dev/null || true
    tc qdisc del dev "$VPN_DEV" ingress 2>/dev/null || true

    if ip link show "$IFB_DEV" >/dev/null 2>&1; then
        tc qdisc del dev "$IFB_DEV" root 2>/dev/null || true
        ip link set "$IFB_DEV" down 2>/dev/null || true
        ip link delete "$IFB_DEV" 2>/dev/null || true
    fi
    sleep 0.2

    if ! ip link add "$IFB_DEV" type ifb 2>/dev/null; then
        if ! ip link show "$IFB_DEV" >/dev/null 2>&1; then
            log "❌ 无法创建 $IFB_DEV"
            return 1
        fi
    fi
    ip link set "$IFB_DEV" up || { log "❌ 无法启动 $IFB_DEV"; return 1; }

    tc qdisc add dev "$VPN_DEV" root handle 1: htb default 1 2>/dev/null || true
    tc class add dev "$VPN_DEV" parent 1: classid 1:1 htb rate 100Mbit ceil 100Mbit 2>/dev/null || true

    tc qdisc add dev "$VPN_DEV" ingress 2>/dev/null || true
    if ! tc filter show dev "$VPN_DEV" parent ffff: 2>/dev/null | grep -q "mirred egress redirect dev $IFB_DEV"; then
        tc filter add dev "$VPN_DEV" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_DEV" 2>/dev/null || true
    fi

    tc qdisc add dev "$IFB_DEV" root handle 2: htb default 1 2>/dev/null || true
    tc class add dev "$IFB_DEV" parent 2: classid 2:1 htb rate 100Mbit ceil 100Mbit 2>/dev/null || true

    log "✅ TC root 初始化完成（classid 池 ${CLASSID_START}-${CLASSID_END}）"

    # 从已有 tc 状态恢复内存映射，避免重启冲突
    rebuild_state || true

    return 0
}

#####################################
# 从现有 tc 状态恢复 classid 使用情况
# 目的：避免 daemon 重启后 classid 冲突
# 不做任何 add / del / 上下线判断
#####################################
rebuild_state() {
    CLASSID_USED=()

    # VPN_DEV (1:)
    if tc class show dev "$VPN_DEV" 2>/dev/null | grep -q "htb"; then
        while read -r line; do
            if [[ "$line" =~ classid[[:space:]]+1:([0-9]+) ]]; then
                cid="${BASH_REMATCH[1]}"
                if (( cid >= CLASSID_START && cid <= CLASSID_END )); then
                    CLASSID_USED["$cid"]=1
                fi
            fi
        done < <(tc class show dev "$VPN_DEV" 2>/dev/null)
    fi

    # IFB_DEV (2:) —— 双保险
    if tc class show dev "$IFB_DEV" 2>/dev/null | grep -q "htb"; then
        while read -r line; do
            if [[ "$line" =~ classid[[:space:]]+2:([0-9]+) ]]; then
                cid="${BASH_REMATCH[1]}"
                if (( cid >= CLASSID_START && cid <= CLASSID_END )); then
                    CLASSID_USED["$cid"]=1
                fi
            fi
        done < <(tc class show dev "$IFB_DEV" 2>/dev/null)
    fi

    log "🔄 rebuild_state: 已恢复 ${#CLASSID_USED[@]} 个已占用 classid"
}



#####################################
# classid 分配（基于 CLASSID_USED）
#####################################
alloc_classid() {
    ALLOCATED_CLASSID=""
    for ((i=CLASSID_START; i<=CLASSID_END; i++)); do
        if [[ -z "${CLASSID_USED[$i]:-}" ]]; then
            CLASSID_USED[$i]=1
            ALLOCATED_CLASSID="$i"
            return 0
        fi
    done
    log "❌ classid 池已耗尽"
    return 1
}

free_classid() {
    local classid="$1"
    unset CLASSID_USED[$classid]
}

#####################################
# 客户端上线（幂等：检测存在后才创建）
#####################################
add_client() {
    local user="$1"
    local ip="$2"
    if [[ -n "${IP_CLASS_MAP[$ip]:-}" ]]; then
        log "🟡 客户端 $ip 已存在映射，跳过创建"
        return 0
    fi

    if ! alloc_classid; then
        log "❌ 无可用 classid，为 $user ($ip) 放弃"
        return 1
    fi
    local cid="$ALLOCATED_CLASSID"

    read RATE_UP RATE_DOWN <<< "$(get_user_rate "$user")"

    if ! class_exists "$VPN_DEV" "1:" "$cid"; then
        tc class add dev "$VPN_DEV" parent 1:1 classid 1:$cid htb rate "$RATE_UP" ceil "$RATE_UP" 2>/dev/null || true
    else
        log "ℹ class 1:$cid 已存在（$VPN_DEV）"
    fi

    if ! filter_exists_dst "$VPN_DEV" "1:" "$ip"; then
        tc filter add dev "$VPN_DEV" protocol ip parent 1: prio "$cid" flower dst_ip "$ip" flowid 1:$cid 2>/dev/null || true
    else
        log "ℹ filter (dst $ip) 已存在于 $VPN_DEV"
    fi

    if ! class_exists "$IFB_DEV" "2:" "$cid"; then
        tc class add dev "$IFB_DEV" parent 2:1 classid 2:$cid htb rate "$RATE_DOWN" ceil "$RATE_DOWN" 2>/dev/null || true
    else
        log "ℹ class 2:$cid 已存在（$IFB_DEV）"
    fi

    if ! filter_exists_src "$IFB_DEV" "2:" "$ip"; then
        tc filter add dev "$IFB_DEV" protocol ip parent 2: prio "$cid" flower src_ip "$ip" flowid 2:$cid 2>/dev/null || true
    else
        log "ℹ filter (src $ip) 已存在于 $IFB_DEV"
    fi

    IP_CLASS_MAP["$ip"]="$user:$cid"

    log "🟢 客户端上线: $user ($ip) ↑$RATE_UP ↓$RATE_DOWN → class 1:$cid / 2:$cid"
    return 0
}

#####################################
# 客户端下线（只删除存在项，避免抖动导致重复删除错误）
#####################################
del_client() {
    local ip="$1"
    local entry="${IP_CLASS_MAP[$ip]:-}"
    if [[ -z "$entry" ]]; then
        log "⚠ 下线: $ip 无内存记录，跳过"
        return 0
    fi

    local user="${entry%:*}"
    local classid="${entry##*:}"

    unset IP_CLASS_MAP["$ip"]
    free_classid "$classid"

    log "🔴 客户端下线: ${user:-UNKNOWN} ($ip) → 删除 class $classid"

    if filter_exists_dst "$VPN_DEV" "1:" "$ip"; then
        tc filter del dev "$VPN_DEV" parent 1: protocol ip prio "$classid" flower dst_ip "$ip" 2>/dev/null || true
    else
        log "ℹ $VPN_DEV 上无 dst filter $ip"
    fi

    if filter_exists_src "$IFB_DEV" "2:" "$ip"; then
        tc filter del dev "$IFB_DEV" parent 2: protocol ip prio "$classid" flower src_ip "$ip" 2>/dev/null || true
    else
        log "ℹ $IFB_DEV 上无 src filter $ip"
    fi

    if class_exists "$VPN_DEV" "1:" "$classid"; then
        tc class del dev "$VPN_DEV" classid 1:$classid 2>/dev/null || true
    fi
    if class_exists "$IFB_DEV" "2:" "$classid"; then
        tc class del dev "$IFB_DEV" classid 2:$classid 2>/dev/null || true
    fi

    log "✅ 客户端下线完成: ${user:-UNKNOWN} ($ip) → class $classid 已删除"
    return 0
}

#####################################
# 解析 status.log（稳健，不存在时不失败）
#####################################
parse_clients() {
    if [[ ! -f "$STATUS_LOG" ]]; then
        return 0
    fi

    # 使用 awk 去除前后空白并打印 user ip（user 在第2列，ip 在第1列）
    awk -F, '
        function trim(s) {
            sub(/^[ \t\r\n]+/, "", s);
            sub(/[ \t\r\n]+$/, "", s);
            return s;
        }
        /^ROUTING TABLE/ { in_section=1; next }
        /^GLOBAL STATS/ { in_section=0 }
        in_section && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            ip = trim($1)
            user = trim($2)
            if (ip != "" && user != "") {
                # 输出 user 然后 ip（与主循环解析保持一致）
                print user " " ip
            }
        }
    ' "$STATUS_LOG" 2>/dev/null || true
}



#####################################
# 自愈函数功能
#####################################

# 检查设备是否存在根 qdisc
root_qdisc_exists() {
    local dev="$1"
    local handle="${2:-1}"  # 默认 root handle 1
    tc qdisc show dev "$dev" | grep -q "htb ${handle}:"
}

# 检查设备是否存在指定 class 的父类
parent_class_exists() {
    local dev="$1"
    local parent="$2"   # 1:1 or 2:1
    tc class show dev "$dev" | grep -q "class htb $parent"
}

# 确保 root+parent 存在(repair_client 前置检查)
ensure_tc_base() {
    local dev="$1"
    local parent="$2"   # 1:1 or 2:1
    local root_handle="${parent%%:*}"  # 提取父类号作为 root handle

    if ! root_qdisc_exists "$dev" "$root_handle"; then
        log "⚠️  $dev root qdisc 不存在，repair_client 放弃"
        return 1
    fi

    if ! parent_class_exists "$dev" "$parent"; then
        log "⚠️  $dev parent $parent 不存在，repair_client 放弃"
        return 1
    fi

    return 0
}



# 自愈函数
repair_client() {
    local user="$1"
    local ip="$2"

    # 必须有内存映射
    if [[ -z "${IP_CLASS_MAP[$ip]:-}" ]]; then
        log "⚠️ repair_client: $ip 无 IP_CLASS_MAP 记录，跳过"
        return
    fi

    local entry="${IP_CLASS_MAP[$ip]}"
    local classid="${entry##*:}"

    read RATE_UP RATE_DOWN <<< "$(get_user_rate "$user")"

    local repaired=0

    # === 0️⃣ 基础结构校验（致命） ===
    ensure_tc_base "$VPN_DEV" "1:1" || return
    ensure_tc_base "$IFB_DEV" "2:1" || return

    # === 1️⃣ uplink class ===
    if ! class_exists "$VPN_DEV" "1:" "$classid"; then
        if tc class add dev "$VPN_DEV" parent 1:1 classid 1:$classid htb \
            rate "$RATE_UP" ceil "$RATE_UP" 2>/dev/null; then
            log "🛠 创建 tun0 class 1:$classid"
            repaired=1
        else
            log "❌ 创建 tun0 class 1:$classid 失败"
            return
        fi
    fi

    # === 2️⃣ uplink filter ===
    if ! filter_exists_dst "$VPN_DEV" "1:" "$ip"; then
        if tc filter add dev "$VPN_DEV" protocol ip parent 1: \
            prio "$classid" flower dst_ip "$ip" flowid 1:$classid 2>/dev/null; then
            repaired=1
        else
            log "❌ 添加 tun0 filter dst_ip=$ip 失败"
            return
        fi
    fi

    # === 3️⃣ downlink class ===
    if ! class_exists "$IFB_DEV" "2:" "$classid"; then
        if tc class add dev "$IFB_DEV" parent 2:1 classid 2:$classid htb \
            rate "$RATE_DOWN" ceil "$RATE_DOWN" 2>/dev/null; then
            repaired=1
        else
            log "❌ 创建 ifb0 class 2:$classid 失败"
            return
        fi
    fi

    # === 4️⃣ downlink filter ===
    if ! filter_exists_src "$IFB_DEV" "2:" "$ip"; then
        if tc filter add dev "$IFB_DEV" protocol ip parent 2: \
            prio "$classid" flower src_ip "$ip" flowid 2:$classid 2>/dev/null; then
            repaired=1
        else
            log "❌ 添加 ifb0 filter src_ip=$ip 失败"
            return
        fi
    fi

    if (( repaired == 1 )); then
        log "🛠 修复 tc 规则: $user ($ip) class=$classid"
    fi
}



#####################################
# 主循环
#####################################
log "========================================="
log "VPN TC 守护进程启动"
log "status.log 路径: $STATUS_LOG"
log "VPN 设备: $VPN_DEV"
log "========================================="

retry_count=0
max_retries=5
while ! init_tc; do
    ((retry_count++))
    if [[ $retry_count -ge $max_retries ]]; then
        log "❌ TC 初始化失败，退出"
        exit 1
    fi
    log "⚠️ TC 初始化失败，5 秒后重试 ($retry_count/$max_retries)..."
    sleep 5
done

log "✅ 服务启动完成，开始监控客户端连接"


while true; do
    mapfile -t CURRENT < <(parse_clients)

    declare -A CURRENT_MAP=()

    # ========= 构建当前快照 =========
    for line in "${CURRENT[@]}"; do
        [[ -z "${line//[[:space:]]/}" ]] && continue

        user=$(awk '{print $1}' <<<"$line" | tr -d '\r')
        ip=$(awk '{print $2}' <<<"$line" | tr -d '\r')

        [[ -z "$user" || -z "$ip" ]] && continue
        CURRENT_MAP["$ip"]="$user"
    done

    # ========= 新上线 =========
    for ip in "${!CURRENT_MAP[@]}"; do
        user="${CURRENT_MAP[$ip]}"

        if [[ -z "${LAST_SEEN[$ip]:-}" ]]; then
            add_client "$user" "$ip" || true
        fi
    done

    # ========= 下线 =========
    for ip in "${!LAST_SEEN[@]}"; do
        if [[ -z "${CURRENT_MAP[$ip]:-}" ]]; then
            del_client "$ip" || true
        fi
    done

    # ========= 稳态修复（降频） =========
    REPAIR_TICK=$((REPAIR_TICK + 1))

    if (( REPAIR_TICK >= REPAIR_INTERVAL )); then
        for ip in "${!CURRENT_MAP[@]}"; do
            user="${CURRENT_MAP[$ip]}"
            if [[ -n "${IP_CLASS_MAP[$ip]:-}" ]]; then
                repair_client "$user" "$ip" || true
            fi
        done
        REPAIR_TICK=0
    fi

    # ========= 更新快照 =========
    LAST_SEEN=()
    for ip in "${!CURRENT_MAP[@]}"; do
        LAST_SEEN["$ip"]="${CURRENT_MAP[$ip]}"
    done

    sleep "$INTERVAL"
done
