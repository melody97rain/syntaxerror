#!/bin/bash
# XRAY VMESS WS
data=( `cat /usr/local/etc/xray/config.json | grep '^#vms' | cut -d ' ' -f 2`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^#vms $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" = "0" ]]; then
sed -i "/^#vms $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
sed -i "/^#vms $user $exp/,/^},{/d" /usr/local/etc/xray/none.json
systemctl disable xray@$user-tls.service
systemctl stop xray@$user-tls.service
systemctl disable xray@$user-none.service
systemctl stop xray@$user-none.service
rm -f "/usr/local/etc/xray/$user-tls.json"
rm -f "/usr/local/etc/xray/$user-none.json"
rm -f "/usr/local/etc/xray/$user-clash-for-android.yaml"
rm -f "/home/vps/public_html/$user-clash-for-android.yaml"
fi
done
systemctl restart xray
systemctl restart xray@none
# XRAY VLESS WS
data=( `cat /usr/local/etc/xray/config.json | grep '^#vls' | cut -d ' ' -f 2`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^#vls $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" = "0" ]]; then
sed -i "/^#vls $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
sed -i "/^#vls $user $exp/,/^},{/d" /usr/local/etc/xray/none.json
fi
done
systemctl restart xray
systemctl restart xray@none
# XRAY TROJAN TCP TLS
data=( `cat /usr/local/etc/xray/akunxtr.conf | grep '^###' | cut -d ' ' -f 2`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^### $user" "/usr/local/etc/xray/akunxtr.conf" | cut -d ' ' -f 3)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" = "0" ]]; then
sed -i "/^#trx $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
sed -i "/^### $user $exp/d" "/usr/local/etc/xray/akunxtr.conf"
fi
done
systemctl restart xray
# XRAY VLESS XTLS DIRECT
data=( `cat /usr/local/etc/xray/config.json | grep '^#vxtls' | cut -d ' ' -f 2`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^#vxtls $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" = "0" ]]; then
sed -i "/^#vxtls $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
fi
done
systemctl restart xray
# TROJAN GO
data=( `cat /etc/trojan-go/akun.conf | grep '^###' | cut -d ' ' -f 2`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^### $user" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 3)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" = "0" ]]; then
sed -i '/^,"'"$user"'"$/d' /etc/trojan-go/config.json
sed -i "/^### $user $exp/d" "/etc/trojan-go/akun.conf"
fi
done
systemctl restart trojan-go

# oyenvpn tambah
#----- Auto Remove Vless
data=( `cat /usr/local/etc/xray/config.json | grep '^#vls' | cut -d ' ' -f 2 | sort | uniq`);
now=`date +"%Y-%m-%d"`
for user in "${data[@]}"
do
exp=$(grep -w "^#vls $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
if [[ "$exp2" -le "0" ]]; then
sed -i "/^#vls $user $exp/,/^},{/d" /usr/local/etc/xray/config.json
sed -i "/^#vls $user $exp/,/^},{/d" /usr/local/etc/xray/none.json
fi
done;sleep 5
systemctl restart xray;sleep 5
systemctl restart xray@none
echo "done clear user exp"
read -p "$( echo -e "Press ${orange}[ ${NC}${green}Enter${NC} ${CYAN}]${NC} Back to menu . . .") "
menu
sleep 1
