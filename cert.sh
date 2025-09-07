#!/bin/bash
echo ""
echo -e "   .-----------------------------------."
echo -e "   |   \e[1;32mPlease select acme for domain\e[0m   |"
echo -e "   '-----------------------------------'"
echo -e "     \e[1;32m1)\e[0m ZeroSSL.com"
echo -e "     \e[1;32m2)\e[0m BuyPass.com"
echo -e "     \e[1;32m3)\e[0m Letsencrypt.org"
echo -e "   ------------------------------------"
read -p "   Please select numbers 1-3(Any Button Default Letsencrypt.org) : " acmee
acme1=zerossl
acme2=https://api.buypass.com/acme/directory
acme3=letsencrypt
if [[ $acmee == "1" ]]; then
echo -e "ZeroSSL.com acme is used"
acmeh=$acme1
echo ""
elif [[ $acmee == "2" ]]; then
echo -e "BuyPass.com acme is used"
acmeh=$acme2
elif [[ $acmee == "3" ]]; then
echo -e "Letsencrypt.org acme is used"
acmeh=$acme3
else
echo -e "Default acme(Letsencrypt.org) is used"
acmeh=$acme3
clear
fi
clear
echo start
sleep 0.5
source /var/lib/premium-script/ipvps.conf
domain=$(cat /usr/local/etc/xray/domain)
emailcf=$(cat /usr/local/etc/xray/email)
clear
echo ""
cek=$(netstat -nutlp | grep -w 80)
if [[ -z $cek ]]; then
clear
systemctl stop xray
systemctl stop trojan-go
echo -e "\e[0;32mStart renew your Certificate SSL\e[0m"
sleep 1
/root/.acme.sh/acme.sh --server $acmeh \
        --register-account  --accountemail $emailcf
/root/.acme.sh/acme.sh --server $acmeh --issue -d $domain --standalone -k ec-256 --force
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /usr/local/etc/xray/xray.crt --keypath /usr/local/etc/xray/xray.key --ecc
systemctl start xray
systemctl start trojan-go
echo Done
sleep 0.5
echo -e "[${GREEN}Done${NC}]"
else
echo -e "\e[1;32mPort 80 is used\e[0m"
echo -e "\e[1;31mBefore renew domains, make sure port 80 is not used, if you are not sure whether port 80 is in use, please type info to see the active port.\e[0m"
sleep 1
fi
