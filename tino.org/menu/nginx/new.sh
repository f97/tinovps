admin_port="7979"
sock_tino=$(php -v | head -n 1 | cut -d " " -f 2 | cut -f1-2 -d"." |  sed -e 's/\.//g')
system_version=$(rpm -E %{rhel})

# @author: Lãng Tử Cô Độc
# @website:  https://tinohost.com, https://kienthuclinux.com
# @since: 2020


CREATE_STARTUP_SCRIPT_NGX() {

mkdir -p /var/cache/nginx  >/dev/null 2>&1
mkdir -p /var/log/nginx  >/dev/null 2>&1


cat > "/etc/nginx/nginx.conf" <<END
user nginx nginx;
worker_processes auto;
worker_rlimit_nofile 8192;

error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
include /usr/share/nginx/modules/*.conf;
pcre_jit on;

events
{
	worker_connections 1024;
	use epoll;
}

http
{
	server_names_hash_max_size 2048;
	server_tokens off;
	more_set_headers 'Server: tino-panel';
	vhost_traffic_status_zone;

	geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb
	{
		auto_reload 60m;
		\$geoip2_metadata_country_build metadata build_epoch;
		\$geoip2_data_country_code country iso_code;
		\$geoip2_data_country_name country names en;
	}
	geoip2 /usr/share/GeoIP/GeoLite2-City.mmdb
	{
		auto_reload 60m;
		\$geoip2_metadata_city_build metadata build_epoch;
		\$geoip2_data_city_name city names en;
	}

	add_header X-GeoCountry \$geoip2_data_country_name;
	add_header X-GeoCode \$geoip2_data_country_code;
	add_header X-GeoCity \$geoip2_data_city_name;

	map \$geoip2_data_country_code \$allowed_country
	{
		default yes;
		VN yes;
		US yes;
	}


	geo \$whitelist
	{
		default 0;
		# CIDR in the list below are not limited
		1.2.3.0/24 1;
		9.10.11.12/32 1;
		127.0.0.1/32 1;
		#     $server_ip 1;
	}

	map \$whitelist \$limit
	{
		0 \$binary_remote_addr;
		1 "";
	}


	map \$http_host \$blogid
	{
		default -999;
	}
	geo \$allowed_ip
	{
		default yes;
		127.0.0.1 yes;
		192.168.1.0/24 yas;
	}
	server_names_hash_bucket_size 1024;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
	'\$status \$body_bytes_sent "\$http_referer" '
	'"\$http_user_agent" "\$http_x_forwarded_for" '
	'\$request_time \$upstream_response_time \$pipe';

	disable_symlinks if_not_owner;

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	types_hash_max_size 2048;
	variables_hash_max_size 1024;
	variables_hash_bucket_size 128;

	keepalive_requests 300;
	keepalive_timeout 30;

	client_body_temp_path /var/lib/nginx/cache/client_body 1 2;
	client_max_body_size 512M;
	client_body_buffer_size 2048k;
	client_body_timeout 30s;
	client_header_timeout 30s;

	connection_pool_size 256;


	## Include Gzip-brotli
	include /etc/nginx/gzip.conf;

	## General Options
	index index.html index.php;
	charset UTF-8;
	ignore_invalid_headers on;

	## pagespeed options
	include /etc/nginx/pagespeed.conf;

	## proxy - fast cgi options
	include /etc/nginx/proxy.conf;


	upstream php
	{
		#server 127.0.0.1:9000;
		server unix:/dev/shm/tinopanel.$sock_tino.sock;
	}

	include /etc/nginx/conf.d/vhosts/*.conf;
	include /etc/nginx/conf.d/custom/blacklist.conf;
	include /etc/nginx/conf.d/custom/cloudflare.conf;
}
END

cat > "/etc/nginx/gzip.conf" <<END
    brotli on;
    brotli_static on;
    brotli_buffers 16 8k;
    brotli_comp_level 6;
    brotli_types
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/vnd.ms-fontobject
        font/truetype
        font/opentype
        image/svg+xml;
        
    gzip on;
    gzip_disable "MSIE [1-6]\.";
    gzip_static on;
    gzip_comp_level 9;
    gzip_http_version 1.1;
    gzip_proxied any;
    gzip_vary on;
    gzip_buffers 16 8k;
    gzip_min_length 1100;
    gzip_types
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/vnd.ms-fontobject
        font/truetype
        font/opentype
        image/svg+xml;
END

cat > "/etc/nginx/pagespeed.conf" <<END

    pagespeed off;
    pagespeed FileCachePath /var/lib/nginx/cache/pagespeed;
    pagespeed FileCacheSizeKb 204800;
    pagespeed FileCacheCleanIntervalMs 3600000;
    pagespeed FileCacheInodeLimit 100000;
    pagespeed MemcachedThreads 1;
    pagespeed MemcachedServers "localhost:11211";
    pagespeed MemcachedTimeoutUs 100000;
    pagespeed RewriteLevel CoreFilters;
    pagespeed EnableFilters collapse_whitespace,remove_comments,extend_cache;
    pagespeed DisableFilters combine_css,combine_javascript;
    pagespeed LowercaseHtmlNames on;
    pagespeed StatisticsPath /ngx_pagespeed_statistics;
    pagespeed GlobalStatisticsPath /ngx_pagespeed_global_statistics;
    pagespeed MessagesPath /ngx_pagespeed_message;
    pagespeed ConsolePath /pagespeed_console;
    pagespeed AdminPath /pagespeed_admin;
    pagespeed GlobalAdminPath /pagespeed_global_admin;
    pagespeed MessageBufferSize 100000;
    pagespeed UsePerVhostStatistics on;
    pagespeed FetchHttps enable;
    pagespeed FetchHttps enable,allow_self_signed;
    pagespeed SslCertDirectory /etc/pki/tls/certs;
    pagespeed SslCertFile /etc/pki/tls/cert.pem;
    pagespeed EnableCachePurge on;
    pagespeed InPlaceResourceOptimization on;
    
END


if (( ${system_version} == 9 ));then
    echo "" > /etc/nginx/pagespeed.conf
fi

    
cat > "/etc/nginx/proxy.conf" <<END
    proxy_cache_path /var/lib/nginx/cache/proxy levels=1:2 keys_zone=PROXYCACHE:100m max_size=200m inactive=60m;
    proxy_temp_path /var/lib/nginx/cache/proxy_tmp;
    proxy_connect_timeout 30;
    proxy_read_timeout 300;
    proxy_send_timeout 300;
    proxy_buffers 16 32k;
    proxy_buffering on;
    proxy_buffer_size 64k;
    proxy_busy_buffers_size 96k;
    proxy_temp_file_write_size 96k;
    proxy_cache_key "\$scheme://\$host\$request_uri";

    fastcgi_cache_path /var/lib/nginx/cache/fastcgi levels=1:2 keys_zone=FCGICACHE:100m max_size=200m inactive=60m;
    fastcgi_temp_path /var/lib/nginx/cache/fastcgi_tmp;
    fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
    fastcgi_cache_use_stale error timeout invalid_header http_500;
    fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffers 8 256k;
    fastcgi_buffer_size 256k;
    fastcgi_busy_buffers_size 256k;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    
    #limit_req_zone \$binary_remote_addr zone=wplogin:50m rate=15r/m;
	limit_req_zone       \$limit   zone=wplogin:10m  rate=60r/m;
    #limit_req            zone=wplogin burst=3;
    #limit_req_log_level  warn;
    #limit_req_status     503;
END


cat > "/etc/nginx/fastcgi.conf" <<END
fastcgi_param  SCRIPT_FILENAME    \$document_root\$fastcgi_script_name;
fastcgi_param  QUERY_STRING	  \$query_string;
fastcgi_param  REQUEST_METHOD     \$request_method;
fastcgi_param  CONTENT_TYPE	  \$content_type;
fastcgi_param  CONTENT_LENGTH     \$content_length;

fastcgi_param  SCRIPT_NAME        \$fastcgi_script_name;
fastcgi_param  REQUEST_URI        \$request_uri;
fastcgi_param  DOCUMENT_URI	  \$document_uri;
fastcgi_param  DOCUMENT_ROOT	  \$document_root;
fastcgi_param  SERVER_PROTOCOL    \$server_protocol;
fastcgi_param  REQUEST_SCHEME     \$scheme;
fastcgi_param  HTTPS              \$https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/\$nginx_version;

fastcgi_param  REMOTE_ADDR        \$remote_addr;
fastcgi_param  REMOTE_PORT        \$remote_port;
fastcgi_param  SERVER_ADDR        \$server_addr;
fastcgi_param  SERVER_PORT        \$server_port;
fastcgi_param  SERVER_NAME        \$server_name;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
fastcgi_param  REDIRECT_STATUS    200;
END
cat > "/etc/nginx/fastcgiproxy.conf" <<END
set_real_ip_from 199.27.128.0/21;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
END
}


CREATE_USER_NGINX() {
	if [ ! `cat /etc/passwd | grep nginx` ]; then
		groupadd -r nginx 
        useradd -r -s /sbin/nologin -M -c "nginx service" -g nginx nginx
		echo "Finished create user nginx, continues create startup script..."
		sleep 5
	else
		echo "existed user nginx, continues create startup script..."
		sleep 5
fi
}

echo ""
echo "====================================================================================="
echo "Menu Board > Manage Setting Nginx > Update installed NginX"
echo "/-------------------------/"
echo "- Update installed NginX"
echo "/-----------------------------------------------------------------------------------/"



echo "Viec cap nhat nginx cai dat la khong can thiet neu server on dinh.."
echo "Chi rebuild Vhost trong truong hop nginx update ban stable moi, hoac la nginx bi hong khong the fix thu cong"
echo "thoi gian cai dat khoang 30 phut, trong thoi gian cai dat, ban co the thoat ra, chuong trinh de dung cap nhat nginx"
echo "chuan bi cai dat trong 30s"

sleep 10
yum update -y
sudo yum install libzip5 -y

mkdir -p /etc/nginx/html
cd /etc/nginx/html

wget --no-check-certificate --backups=1 https://scripts.tino.org/tino-nginx/TEM/aes.min.js
wget --no-check-certificate  --backups=1 https://scripts.tino.org/tino-nginx/TEM/captcha.html


# tai nginx
#NGINX_VERSION=1.22.1

nginx_version="1.24.0"
release_nginx="2"
cd /root/
wget --no-check-certificate https://scripts.tino.org/repo_nginx/nginx-$nginx_version-$release_nginx.el$system_version.x86_64.rpm
wget --no-check-certificate https://scripts.tino.org/repo_nginx/nginx-module-modsecurity-$nginx_version-$release_nginx.el$system_version.x86_64.rpm
wget --no-check-certificate https://scripts.tino.org/repo_nginx/libmaxminddb-1.7.1-1.el$system_version.x86_64.rpm


yum localinstall /root/nginx-$nginx_version-$release_nginx.el$system_version.x86_64.rpm -y
yum localinstall /root/nginx-module-modsecurity-$nginx_version-$release_nginx.el$system_version.x86_64.rpm -y
yum localinstall  /root/libmaxminddb-1.7.1-1.el$system_version.x86_64.rpm -y


yum localinstall  /root/*.rpm -y
rm -rf /root/*.rpm

yum install geolite2-city -y
yum -y install geolite2-country



rm -rf /usr/local/modsecurity-crs
git clone https://github.com/coreruleset/coreruleset /usr/local/modsecurity-crs
echo "yes"| mv /usr/local/modsecurity-crs/crs-setup.conf.example /usr/local/modsecurity-crs/crs-setup.conf
echo "yes"| mv /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
 mkdir -p /etc/nginx/modsec
echo "yes"| cp /opt/ModSecurity/unicode.mapping /etc/nginx/modsec
echo "yes"|cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's#SecAuditLog /var/log/modsec_audit.log#SecAuditLog /dev/null#' /etc/nginx/modsec/modsecurity.conf
sed -i 's#SecAuditEngine RelevantOnly#SecAuditEngine off#' /etc/nginx/modsec/modsecurity.conf

cat > "/etc/nginx/modsec/main.conf" <<END
Include /etc/nginx/modsec/modsecurity.conf
Include /usr/local/modsecurity-crs/crs-setup.conf
Include /usr/local/modsecurity-crs/rules/*.conf
END


sleep 5
echo "xu ly cai dat lai file cau hinh"
CREATE_STARTUP_SCRIPT_NGX

sleep 5
mkdir -p /etc/nginx/conf.d/

cd /etc/nginx/conf.d/

wget --no-check-certificate  https://scripts.tino.org/tino.zip
yes|unzip tino*
rm -rf tino.zip


cat > "/etc/nginx/conf.d/vhosts/phpmyadmin.conf" <<END
upstream netdata {
server 127.0.0.1:19999;
keepalive 64;
}
server {
	listen $admin_port default_server;
	listen 80;
	server_name _;
	root /opt/tinopanel/private_html;
	access_log /var/log/nginx/default-access_log;
	error_log /var/log/nginx/default-error_log warn;
 #   modsecurity on;
 #   modsecurity_rules_file /etc/nginx/modsec/main.conf;
    satisfy any;
    allow 127.0.0.1;
    deny all;
 
	auth_basic "Restricted";
	auth_basic_user_file /opt/tinopanel/ssl/.htpasswd;
	if (\$bad_bot) { return 444; }
	
	server_name_in_redirect off;

	#include conf.d/custom/restrictions.conf;
	#include conf.d/custom/pagespeed.conf;


  location /vts_status {
    vhost_traffic_status_bypass_limit on;
    vhost_traffic_status_bypass_stats on;
    vhost_traffic_status_display;
    vhost_traffic_status_display_format html;
  }
	
	location /stub_status {
	stub_status;
	allow 127.0.0.1;	#only allow requests from localhost
	deny all;
	}
	 
	location /nginx_status {
        stub_status on;
        access_log off;
        include conf.d/custom/admin-ips.conf; deny all;
    } 
      location /netdata {
        return 301 /netdata/;
   }

   location ~ /netdata/(?<ndpath>.*) {
        proxy_redirect off;
        proxy_set_header Host \$host;

        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Server \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_pass_request_headers on;
        proxy_set_header Connection "keep-alive";
        proxy_store off;
        proxy_pass http://netdata/\$ndpath\$is_args\$args;

    }


    location ~ ^/(status|ping)\$ {
	fastcgi_pass php; 
       access_log off;
    }
    	include conf.d/custom/fpm-default.conf;
}
END


cd /etc/nginx/
#wget --no-check-certificate  https://scripts.tino.org/dhparam.pem
openssl dhparam -out /etc/nginx/dhparam.pem 2048

mkdir -p /etc/nginx/conf.d/addon_confs
mkdir -p /etc/nginx/conf.d/ssl

systemctl start nginx.service
systemctl enable nginx.service
systemctl daemon-reload



for D in /etc/quicklemp/domains/*; do
if [ -d "${D}" ]; then #If a directory
domain=${D##*/}
domain_alias="www.$domain"
    if [[ $domain == *www* ]]; then
	    domain_alias=${domain/www./''}
    fi
echo "rebuild lai vhost cho domain $domain"          			
php_dir=$(</etc/quicklemp/domains/$domain/php_dir)
user=$(</etc/quicklemp/domains/$domain/user)
php_version=$(</etc/quicklemp/domains/$domain/php_version)
page_speed=$(</etc/quicklemp/domains/$domain/page_speed)
echo ""

php_ver=${php_dir:3}

mkdir -p /etc/nginx/conf.d/addon_confs/$domain/

cp -r /etc/nginx/conf.d/custom/$php_version.conf /etc/nginx/conf.d/addon_confs/$domain/$php_version.conf
cp -r /etc/nginx/conf.d/custom/restrictions-users.conf /etc/nginx/conf.d/addon_confs/$domain/restrictions-users.conf

if ! [ -d "/etc/nginx/conf.d/ssl/$domain/" ] 
then
mkdir -p /etc/nginx/conf.d/ssl/$domain/
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout /etc/nginx/conf.d/ssl/$domain/privkey.key -out /etc/nginx/conf.d/ssl/$domain/chain.pem -subj "/C=US/CN=$domain" &>/dev/null
openssl x509 -outform pem -in /etc/nginx/conf.d/ssl/$domain/chain.pem -out /etc/nginx/conf.d/ssl/$domain/fullchain.crt &>/dev/null
server_ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | sed -e 's/\"//g')
 ip=$(getent hosts $domain | awk '{ print $1 }');
    wwwdomain=www.$domain
    wwwip=$(getent hosts $wwwdomain | awk '{ print $1 }');    
    mkdir -p /etc/nginx/conf.d/ssl/$domain/	
    echo "$domain point to IP: $ip"        
    echo "$wwwdomain point to IP: $wwwip"

	
	if [ "$ip" = "$server_ip" ]; then
		if [ "$wwwip" = "$server_ip" ]; then
			echo "Setup Let's Enscrypt for $domain ... and $wwwdomain "
			/root/.acme.sh/acme.sh  --issue -w /home/$domain/public_html/ -d $domain -d $wwwdomain -k 4096 --force			
				if [ -f /root/.acme.sh/$domain/$domain.cer ]; then
					echo "Installing SSL for domain $domain, $wwwdomain"
					/root/.acme.sh/acme.sh --installcert -d $domain --keypath /etc/nginx/conf.d/ssl/$domain/privkey.key --fullchainpath /etc/nginx/conf.d/ssl/$domain/fullchain.crt
					echo "SSL installation is complete."
				else
					echo "SSL settings encountered an error, please check again."
				fi		
		else		
			echo "Setup Let's Enscrypt for $domain ... no record exists $wwwdomain "			
			/root/.acme.sh/acme.sh  --issue -w /home/$domain/public_html/ -d $domain -k 4096 --force
			if [ -f /root/.acme.sh/$domain/$domain.cer ]; then
				echo "Installing SSL for domain $domain ."
				/root/.acme.sh/acme.sh --installcert -d $domain --keypath /etc/nginx/conf.d/ssl/$domain/privkey.key --fullchainpath /etc/nginx/conf.d/ssl/$domain/fullchain.crt
				echo "SSL installation is complete."
			else
				echo "SSL settings encountered an error, please check again."
			fi
		fi
	else
	    if [ "$wwwip" = "$server_ip" ]; then
		    read -r -p "$wwwdomain pointing to the VPS IP, $domain has not been returned to IP VPS, You still want to personalize it $wwwdomain ? [y/N] " response
            case $response in
                [yY][eE][sS]|[yY])
				
				echo "SSetup Let's Enscrypt for $wwwdomain ... "
				/root/.acme.sh/acme.sh  --issue -w /home/$domain/public_html/ -d $wwwdomain -k 4096 --force
				if [ -f /root/.acme.sh/$domain/$domain.cer ]; then
					echo "Installing SSL for domain $domain"
					/root/.acme.sh/acme.sh --installcert -d $domain --keypath /etc/nginx/conf.d/ssl/$domain/privkey.key --fullchainpath /etc/nginx/conf.d/ssl/$domain/fullchain.crt
					echo "SSL installation is complete."
				else
					echo "SSL settings encountered an error, please check again."
				fi
			esac
		fi
	echo "$domain, $wwwdomain not pointing to IP VPS."		
	fi	
	
fi

if [ "$page_speed" == "yes" ] ; then
cat > "/etc/nginx/conf.d/addon_confs/$domain/page_speed.conf" <<END
pagespeed on;
location /ngx_pagespeed_statistics { include conf.d/custom/admin-ips.conf; deny all; }
location /ngx_pagespeed_global_statistics { include conf.d/custom/admin-ips.conf; deny all; }
location /ngx_pagespeed_message { include conf.d/custom/admin-ips.conf; deny all; }
location /pagespeed_console { include conf.d/custom/admin-ips.conf; deny all; }
location /pagespeed_admin { include conf.d/custom/admin-ips.conf; deny all; }
location /pagespeed_global_admin { include conf.d/custom/admin-ips.conf; deny all; }
location ~ "\.pagespeed\.([a-z]\.)?[a-z]{2}\.[^.]{10}\.[^.]+" { add_header "" ""; }
location ~ "^/ngx_pagespeed_static/" { }
location ~ "^/ngx_pagespeed_beacon$" { }
END

fi


cat > "/opt/php/$php_dir/etc/php-fpm.d/$domain.conf" <<END
[$domain]
listen = /dev/shm/$domain.$php_dir.sock;
user = $user
group = $user
listen.owner = nginx
listen.group = nginx
listen.mode = 0644
pm = ondemand
pm.max_children = 15
pm.start_servers = 5
pm.min_spare_servers = 3
pm.max_spare_servers = 10
pm.max_requests = 500
END

cat > "/etc/quicklemp/domains/$domain/php_dir" <<END
$php_dir
END

   cat > "/etc/nginx/conf.d/vhosts/$domain.conf" <<END
server {
        listen 80;
        server_name $domain $domain_alias;
        root /home/$domain/public_html;

	    access_log /home/$domain/logs/access_log main;
	    error_log /home/$domain/logs/error_log warn;

        if (\$bad_bot) { return 444; }
        set \$fpmuser $domain.$php_dir;
         include conf.d/addon_confs/$domain/*.conf;
		include conf.d/custom/wp-rocket.conf; 
}

END

 cat > "/etc/nginx/conf.d/vhosts/$domain.ssl.conf" <<END
server {
        listen 443 ssl http2;
        server_name $domain $domain_alias;
        root /home/$domain/public_html;
		
	    access_log /home/$domain/logs/access_ssl_log main;
	    error_log /home/$domain/logs/error_ssl_log warn;

        if (\$bad_bot) { return 444; }
        set \$fpmuser $domain.$php_dir;

        include conf.d/ssl/$domain/ssl.conf;
        include conf.d/addon_confs/$domain/*.conf;
		include conf.d/custom/wp-rocket.conf;
}
END
cat > "/etc/nginx/conf.d/ssl/$domain/ssl.conf" <<END
ssl_certificate /etc/nginx/conf.d/ssl/$domain/fullchain.crt;
ssl_certificate_key /etc/nginx/conf.d/ssl/$domain/privkey.key;
#ssl_trusted_certificate /etc/nginx/conf.d/ssl/$domain/chain.pem;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_session_timeout 4h;
ssl_session_cache shared:SSL:20m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
#ssl_ecdh_curve X25519:P-256:P-384:P-224:P-521;
ssl_buffer_size 1400;
#ssl_stapling on;
ssl_stapling_verify on;
#ssl_trusted_certificate /etc/nginx/conf.d/ssl/$domain/chain.pem;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
#add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;

## Modern compatibility
ssl_ciphers TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384;

## Intermediate compatibility
#ssl_ciphers TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS;

## Old backward compatibility
#ssl_ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
END

      fi
if [ "$php_version" = "fpm-laravel-users" ]; then

sed -i "s/$domain\/public_html;/$domain\/public_html\/public;/g" /etc/nginx/conf.d/vhosts/$domain.ssl.conf
sed -i "s/$domain\/public_html;/$domain\/public_html\/public;/g" /etc/nginx/conf.d/vhosts/$domain.conf

fi
done

for D in /opt/php/*; do
if [ -d "${D}" ]; then #If a directory
php_version1=${D##*/}
php_ver=${php_version1:3}
service php-fpm-$php_ver restart &>/dev/null
fi
done

    nginx -s reload
	
/etc/quicklemp/menu/nginx/rebuild_loginadminpage


/etc/quicklemp/menu/nginx_
