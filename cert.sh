#!/bin/bash

# Run as root
u=`id -un`
if [ x$u != "xroot" ]; then
    echo "Error: must be run as root user"
    exit 1
fi

if [ $(dig +short type257 $(hostname --d) | grep "letsencrypt.org" | grep "issue" | wc -l) -ge 1 ]; then   
  echo "Installing certbot"
  apt-get install -y -qq python3 python3-venv libaugeas0 python3-venv > /dev/null
  python3 -m venv /opt/certbot/
  /opt/certbot/bin/pip install --upgrade pip
  /opt/certbot/bin/pip install certbot
  ln -s /opt/certbot/bin/certbot /usr/local/sbin/certbot
  /usr/local/sbin/certbot certonly -d $(hostname --fqdn) --standalone --preferred-chain  "ISRG Root X1" --agree-tos --register-unsafely-without-email
  cat >> /usr/local/sbin/letsencrypt-zimbra << EOF
#!/bin/bash

u=`id -un`
if [ x$u != "xroot" ]; then
    echo "Error: must be run as root user"
    exit 1
fi

MAILTO=""
/usr/local/sbin/certbot certonly -d $(hostname --fqdn) --standalone -n --preferred-chain  "ISRG Root X1" --agree-tos --register-unsafely-without-email

cp "/etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem" /opt/zimbra/ssl/zimbra/commercial/commercial.key
chown zimbra:zimbra /opt/zimbra/ssl/zimbra/commercial/commercial.key
wget -O /tmp/ISRG-X1.pem https://letsencrypt.org/certs/isrgrootx1.pem.txt
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cp "/etc/letsencrypt/live/$(hostname --fqdn)/chain.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cat /tmp/ISRG-X1.pem >> "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
chown zimbra:zimbra /etc/letsencrypt -R
cd /tmp
su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm "/etc/letsencrypt/live/$(hostname --fqdn)/cert.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"'
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
EOF
    chmod +rx /usr/local/sbin/letsencrypt-zimbra
  else 
    echo "CAA record for your domain cannot be found, you should add it first, example for bind:"
    echo "@			CAA     0 issue \"letsencrypt.org\""
    exit 1
fi
