#!/bin/bash

# post install as Zimbra user
# check these values
MYIP=$(hostname -I | cut -f1 -d" " | tr -d '[:space:]')
DOMAIN="zimbra.lab"

# TLS 1.2 only for mailstore
sed -i 's/-server -Dhttps.protocols=TLSv1.2 -Djdk.tls.client.protocols=TLSv1.2/-server -Dhttps.protocols=TLSv1.2,TLSv1.3 -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3/g' /opt/zimbra/conf/localconfig.xml
wget -q https://raw.githubusercontent.com/internetstandards/dhe_groups/master/ffdhe4096.pem -O /etc/ffdhe4096.pem

/opt/zimbra/bin/postconf -e fast_flush_domains=""
/opt/zimbra/bin/postconf -e smtpd_etrn_restrictions=reject
/opt/zimbra/bin/postconf -e disable_vrfy_command=yes
/opt/zimbra/bin/postconf -e tls_medium_cipherlist=$(/opt/zimbra/common/bin/openssl ciphers)
/opt/zimbra/bin/postconf -e tls_preempt_cipherlist=no

/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsprotocolmin="3.3"
/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsciphersuite="HIGH"
/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_supported=1
/opt/zimbra/bin/zmlocalconfig -e zimbra_require_interprocess_security=1
/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_required=true

/opt/zimbra/bin/zmlocalconfig -e alias_login_enabled=false
/opt/zimbra/bin/zmlocalconfig -e zimbra_same_site_cookie="Strict"

cat >> /tmp/provfile << EOF
mcf zimbraPublicServiceProtocol https
mcf zimbraPublicServicePort 443
mcf zimbraPublicServiceHostname $HOSTNAME
mcf zimbraReverseProxySSLProtocols TLSv1.2
mcf +zimbraReverseProxySSLProtocols TLSv1.3
mcf zimbraReverseProxySSLCiphers ""
mcf +zimbraResponseHeader "Strict-Transport-Security: max-age=31536000; includeSubDomains"
mcf +zimbraResponseHeader "X-Content-Type-Options: nosniff"
mcf +zimbraResponseHeader "X-Robots-Tag: noindex"
mcf +zimbraResponseHeader "Referrer-Policy: no-referrer"
mcf zimbraMailKeepOutWebCrawlers TRUE
mcf zimbraSmtpSendAddMailer FALSE
mcf zimbraSSLDHParam /etc/ffdhe4096.pem
mcf zimbraMtaSmtpdTlsCiphers medium
mcf zimbraMtaSmtpdTlsMandatoryCiphers  medium
mcf zimbraMtaSmtpdTlsProtocols '>=TLSv1.2'
mcf zimbraMtaTlsSecurityLevel may
ms $HOSTNAME zimbraPop3CleartextLoginEnabled FALSE
ms $HOSTNAME zimbraImapCleartextLoginEnabled FALSE
mcf zimbraLastLogonTimestampFrequency 1s
mc default zimbraPrefShortEmailAddress FALSE
mc default zimbraFeatureTwoFactorAuthAvailable TRUE
mcf +zimbraMailTrustedIP 127.0.0.1
mcf +zimbraMailTrustedIP $MYIP
mcf +zimbraGalLdapAttrMap manager=manager
mcf zimbraBackupReportEmailSender admin@$DOMAIN zimbraBackupReportEmailRecipients admin@$DOMAIN
ms $HOSTNAME zimbraFileUploadMaxSize 80000000
ms $HOSTNAME zimbraMailContentMaxSize 80000000
mcf zimbraMtaMaxMessageSize 80000000
mcf zimbraFileUploadMaxSize 80000000
mcf zimbraMailContentMaxSize 80000000
EOF
/opt/zimbra/bin/zmprov < /tmp/provfile
