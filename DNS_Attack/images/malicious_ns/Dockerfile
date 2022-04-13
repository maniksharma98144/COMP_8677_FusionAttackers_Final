FROM handsonsecurity/seed-server:bind

# Copy the configuration and zone files
COPY named.conf  zone_malicious.com  zone_facebook.com  /etc/bind/

CMD service named start && tail -f /dev/null
