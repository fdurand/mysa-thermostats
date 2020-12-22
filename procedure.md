# Reverse enginering Mysa app

## Install mitmproxy

pip3 install mitmproxy

## Modify Mysa apk

### Download Mysa apk

https://apkpure.com/mysa/com.getmysa.mysa

### Modify the apk file

apktool d Mysa_v2.8.2_apkpure.com -o Mysa

In Mysa/res/xml/ modify network_security_config.xml file

```
<network-security-config>
      <base-config>
            <trust-anchors>  
                <!-- Trust preinstalled CAs -->  
                <certificates src="system" />  
                <!-- Additionally trust user added CAs -->  
                <certificates src="user" />  
           </trust-anchors>  
      </base-config>
 </network-security-config>
```

#### Recreate the apk file

apktool b Mysa/ -o Mysa-patched.apk

#### Transfert the file on the phone and sign it.

use apk-signer to sign the apk file and install it.

## pptpd

### Setup a PPTP VPN using pptpd

Install pptpd:

apt-get install pptpd
Edit /etc/pptpd.conf and add:

localip [The IP of the interface that the server will listen on]
remoteip [The IP that gets handed out to the client]

Edit /etc/ppp/pptpd-options and add the following:

ms-dns [The DNS server that should be used]
nobsdcomp
noipx 
mtu 1490
mru 1490

Edit /etc/ppp/chap-secrets and add a username and password pair:

username <TAB> * <TAB> password <TAB> *

Start pptpd with the new configuration:

systemctl restart pptpd

Enable IP forwarding:

echo 1 > /proc/sys/net/ipv4/ip_forward

### Redirect SSL traffic to mitmproxy with iptables

iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j  MASQUERADE
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 8080


### Setup mitmproxy

Set SSLKEYLOGFILE so that Wireshark can get the SSL keys from mitmproxy:

export SSLKEYLOGFILE=/root/sslkeylog.log

Run mitmproxy in the same shell:

mitmproxy --mode transparent --set client_certs=~/.mitmproxy/clients/orvibo.com.pem --set rawtcp  --ssl-insecure

#### Configure your android phone

Add the certificate:

Transfer the mitmproxy SSL CA certificate to your phones storage, the certificate should be located in ~/.mitmproxy/mitmproxy-ca-cert.cer. Add the certificate to your phone by going to Settings > Security > Install from storage and importing the certificate.

Connect to the VPN:

Go to Wireless and networks > More > VPN and add a VPN connection for the PPTP server and connect to it.

### Setup Wireshark

Set the SSL key log file:

Go to Edit > Preferences > Protocols > SSL and set (Pre)-Master-Secret log filename to the SSL key log file path.

tshark -i ppp0 -f "port 443" -w /tmp/mysa.pcap

tshark -r /tmp/mysa.pcap -q -z follow,ssl,raw,0 > tmp/raw.data

