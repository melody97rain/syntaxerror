#!/usr/bin/env bash
# cek-all
# Dropbear (on top) + OpenSSH logins + OpenVPN client lists + Summary per user
# Run with root (sudo) so journalctl/ss/lsof can access necessary info.

set -euo pipefail

# temp files for OpenSSH parsing + users list
TMP1="$(mktemp /tmp/cek-ssh-XXXXXX)"
TMP2="$(mktemp /tmp/cek-ssh-XXXXXX)"
USERS_TMP="$(mktemp /tmp/cek-all-users-XXXXXX)"
cleanup() {
  rm -f "$TMP1" "$TMP2" "$USERS_TMP"
}
trap cleanup EXIT

SEED_SINCE="${1:-7 days ago}"

# sed to extract PID USER IP PORT from "Password auth succeeded" lines (IPv4)
SED_EXTRACT_PASS='s/.*dropbear\[\([0-9]\+\)\].*Password auth succeeded for '\''\([^'\'']\+\)'\'' from \([0-9.]\+\):\([0-9]\+\).*/\1 \2 \3 \4/p'

declare -A pid_to_user
declare -A pid_to_ip
declare -A pid_to_port

# Seed from journal (Password auth succeeded entries)
if command -v journalctl >/dev/null 2>&1; then
  while IFS=' ' read -r pid user ip port; do
    [ -z "$pid" ] && continue
    [ -n "$user" ] && pid_to_user["$pid"]="$user"
    [ -n "$ip" ] && pid_to_ip["$pid"]="$ip"
    [ -n "$port" ] && pid_to_port["$pid"]="$port"
  done < <(journalctl --no-pager -u dropbear --since "$SEED_SINCE" -o short-iso 2>/dev/null | sed -n "$SED_EXTRACT_PASS" || true)
fi

# helpers
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

get_addr_from_ss() {
  local pid="$1"
  ss -tnp 2>/dev/null | awk -v p="pid=$pid," 'index($0,p){print $(NF-1); exit}'
}

get_addr_from_lsof() {
  local pid="$1"
  if command -v lsof >/dev/null 2>&1; then
    local out
    out=$(lsof -Pan -p "$pid" -i 2>/dev/null | awk '/ESTABLISHED/ || /->/ { for (i=1;i<=NF;i++) if ($i ~ /->[0-9]/) print $i }' | sed -n '1p' || true)
    if [ -n "$out" ]; then
      if echo "$out" | grep -q '->'; then
        out="${out#*->}"
      fi
      printf '%s' "$out"
    fi
  fi
}

normalize_addr() {
  local addr="$1"
  addr="${addr#[}"
  addr="${addr%]}"
  printf '%s' "$addr"
}

# get list of running dropbear PIDs
pids="$(ps -o pid= -C dropbear 2>/dev/null || true)"
echo
echo "-----=[ Dropbear User Login ]=------"
echo "ID  |  Username  |  IP Address"
echo "------------------------------------"

if [ -z "$pids" ]; then
  echo "(no dropbear process found)"
else
  # populate missing info per pid
  for pid in $pids; do
    [ -z "$pid" ] && continue
    user="${pid_to_user[$pid]:-}"
    ip="${pid_to_ip[$pid]:-}"
    port="${pid_to_port[$pid]:-}"

    if [ -z "$user" ]; then
      user="$(journalctl --no-pager -u dropbear --since "$SEED_SINCE" 2>/dev/null | grep -F "dropbear[$pid]" | sed -n "s/.*Password auth succeeded for '\([^']\+\)'.*/\1/p" | tail -n1 || true)"
      [ -n "$user" ] && pid_to_user["$pid"]="$user"
    fi

    if [ -z "$ip" ] || [ -z "$port" ]; then
      addr="$(get_addr_from_ss "$pid" || true)"
      if [ -z "$addr" ]; then
        addr="$(get_addr_from_lsof "$pid" || true)"
      fi
      addr="$(normalize_addr "${addr:-}")"
      if [ -n "$addr" ]; then
        # split last ':' to ip and port (best-effort; IPv6 handling basic)
        if echo "$addr" | grep -q ']:'; then
          ip="${addr%%]*}"
          ip="${ip#\[}"
          port="${addr##*:}"
        else
          # if there's only one colon, split ip:port
          cnt=$(awk -F: '{print NF-1}' <<<"$addr")
          if [ "$cnt" -eq 1 ]; then
            ip="${addr%:*}"
            port="${addr##*:}"
          else
            ip="$addr"
            port=""
          fi
        fi
        [ -n "$ip" ] && pid_to_ip["$pid"]="$ip"
        [ -n "$port" ] && pid_to_port["$pid"]="$port"
      fi
    fi
  done

  printed=0
  for pid in $pids; do
    [ -z "$pid" ] && continue
    user="${pid_to_user[$pid]:-(unknown)}"
    ip="${pid_to_ip[$pid]:-(unknown)}"
    port="${pid_to_port[$pid]:-}"
    user_lc="$(lower "$user")"
    # skip root
    if [ "$user_lc" = "root" ]; then
      continue
    fi
    # only show if we have both user and ip known
    if [ -z "$user" ] || [ -z "$ip" ] || [ "$user" = "(unknown)" ] || [ "$ip" = "(unknown)" ]; then
      continue
    fi
    if [ -n "$port" ]; then
      ipport="${ip}:${port}"
    else
      ipport="${ip}"
    fi
    printf '%6s - %s - %s\n' "$pid" "$user" "$ipport"
    # append user to USERS_TMP for summary counting
    printf '%s\n' "$user" >> "$USERS_TMP"
    printed=1
  done

  if [ "$printed" -eq 0 ]; then
    echo "(no user login detected)"
  fi
fi

# ---------------------------
# OpenSSH section
# ---------------------------
echo
echo "-----=[ OpenSSH User Login ]=-------"
echo "ID  |  Username  |  IP Address"
echo "------------------------------------"

# choose auth log
LOG=""
if [ -r /var/log/auth.log ]; then
  LOG="/var/log/auth.log"
elif [ -r /var/log/secure ]; then
  LOG="/var/log/secure"
fi

if [ -n "$LOG" ]; then
  grep -i sshd "$LOG" | grep -i "Accepted password for" > "$TMP1" || true

  data=( $(ps aux | grep "\[priv\]" | sort -k 72 2>/dev/null || true | awk '{print $2}') )

  for PID in "${data[@]}"; do
    grep "sshd\\[$PID\\]" "$TMP1" > "$TMP2" || true
    NUM=$(wc -l < "$TMP2" || echo 0)
    if [ "$NUM" -eq 1 ]; then
      USER=$(awk '{print $9}' "$TMP2" 2>/dev/null || true)
      IP=$(awk '{print $11}' "$TMP2" 2>/dev/null || true)
      if [ -z "$USER" ] || [ -z "$IP" ]; then
        LINE=$(cat "$TMP2")
        USER=$(echo "$LINE" | sed -n "s/.*Accepted password for \([[:alnum:]_.-]\+\).*/\1/p" || true)
        IP=$(echo "$LINE" | sed -n "s/.*from \([0-9.]\+\).*/\1/p" || true)
      fi
      printf '%s - %s - %s\n' "$PID" "${USER:-(unknown)}" "${IP:-(unknown)}"
      # append user for summary if known
      if [ -n "${USER:-}" ]; then
        printf '%s\n' "$USER" >> "$USERS_TMP"
      fi
    fi
  done
else
  echo "(no auth log found: /var/log/auth.log or /var/log/secure missing or unreadable)"
fi

# ---------------------------
# OpenVPN TCP
# ---------------------------
if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
  echo
  echo "----=[ OpenVPN TCP User Login ]=----"
  echo "Username  |  IP Address  |  Connected Since"
  echo "------------------------------------"
  # CLIENT_LIST lines: CSV, fields 2=username,3=ip,8=connected_since
  grep -w "^CLIENT_LIST" /etc/openvpn/server/openvpn-tcp.log 2>/dev/null | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' | tee -a "$USERS_TMP" >/dev/null || true
fi

# ---------------------------
# OpenVPN UDP
# ---------------------------
if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
  echo
  echo "----=[ OpenVPN UDP User Login ]=----"
  echo "Username  |  IP Address  |  Connected Since"
  echo "------------------------------------"
  grep -w "^CLIENT_LIST" /etc/openvpn/server/openvpn-udp.log 2>/dev/null | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' | tee -a "$USERS_TMP" >/dev/null || true
fi

# ---------------------------
# SUMMARY: total logins per user
# ---------------------------
echo
echo "-----=[ Total Login Setiap User ]=-----"
if [ -s "$USERS_TMP" ]; then
  # normalize: some openvpn lines include spaces; extract only the username field for those lines
  # We'll create a cleaned username list: for lines containing spaces (OpenVPN printed lines) cut first token
  awk '{print $1}' "$USERS_TMP" | sort | uniq -c | sort -rn | awk '{printf "%-20s %d\n", $2, $1}'
else
  echo "(no logins detected)"
fi
echo "------------------------------------"

# done
exit 0
