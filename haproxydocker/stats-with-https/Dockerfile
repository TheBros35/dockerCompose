FROM haproxy:alpine

USER root

# Apache + mod_php, and supervisor to run multiple processes in one container
RUN apk add --no-cache \
        apache2 \
        apache2-ssl \
        apache2-utils \
        php \
        php-apache2 \
        php-openssl \
        php-session \
        supervisor \
        tzdata

# mod_php is NOT thread-safe, so Apache must run the prefork MPM
# (not the event/worker MPM that's often the Alpine default).
# Also enable ssl_module + its dependency socache_shmcb_module.
RUN sed -i \
        -e 's/^LoadModule mpm_event_module/#LoadModule mpm_event_module/' \
        -e 's/^LoadModule mpm_worker_module/#LoadModule mpm_worker_module/' \
        -e 's/^#\(LoadModule mpm_prefork_module .*\)/\1/' \
        -e 's/^Listen 80/#Listen 80/' \
        /etc/apache2/httpd.conf

RUN mkdir -p \
        /usr/local/etc/haproxy/certs \
        /etc/apache2/ssl \
        /run/apache2 \
        /var/www/localhost/htdocs \
    && rm -f /var/www/localhost/htdocs/index.html \
    && chown -R apache:apache /var/www/localhost/htdocs /run/apache2

# --- HAProxy config (as provided) ---
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY lb.pem /usr/local/etc/haproxy/certs/lb.pem

# --- Apache config ---
COPY apache/ssl.conf /etc/apache2/conf.d/ssl.conf
COPY apache/php.conf /etc/apache2/conf.d/php-handler.conf
COPY apache/lb.crt /etc/apache2/ssl/cert.crt
COPY apache/lb.key /etc/apache2/ssl/key.key

# --- Sample web content ---
COPY stats/index.php /var/www/localhost/htdocs/index.php

# --- Process supervisor ---
COPY supervisord.conf /etc/supervisord.conf

# 80/443 = HAProxy, 8443 = Apache HTTPS
EXPOSE 80 443 8443

# NOTE: your TLS cert/key for HAProxy must be combined into a single PEM
# and mounted at /usr/local/etc/haproxy/certs/lb.pem (see README).
# Your Apache cert/key get mounted separately at /etc/apache2/ssl/.

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]