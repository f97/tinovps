echo "Neu ban su dung may tinh ssh bang terminal cua macOS hay Linux, ban vui long chinh thoi gian man hinh cho cua terminal ssh de tranh out ket noi ssh"
echo "Ban sua thoi gian man hinh doi tai file : ~/.ssh/config"
echo "Neu Du lieu ban khoang 5GB, ban nen chinh gia tri len khoang 600, hoac cao hon"
echo ""
echo "Host *"
echo "ServerAliveInterval 600"
echo "TCPKeepAlive yes"
echo "IPQoS=throughput"
echo ""
echo "Chuan bi thuc hien sau 10s"
sleep 10

number_backup=$(</etc/quicklemp/number_backup)
server_ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | sed -e 's/\"//g')
SERVER_NAME=BACKUP_$server_ip

TIMESTAMP=$(date +"%F")
BACKUP_DIR="/root/backup/$TIMESTAMP"
MYSQL=/usr/bin/mysql
MYSQLDUMP=/usr/bin/mysqldump
SECONDS=0

mkdir -p "$BACKUP_DIR/source"
mkdir -p "$BACKUP_DIR/mysql"

echo "The system is starting to back up the Database";
databases=`$MYSQL -e "SHOW DATABASES;" | grep -Ev "(Database|information_schema|performance_schema|mysql)"`
for db in $databases; do
	$MYSQLDUMP --force --opt $db | gzip > "$BACKUP_DIR/mysql/$db.sql.gz"
done
echo "Finished";
echo '';

echo "The system is starting to back up Website Data";
# Loop through /home directory
for D in /etc/quicklemp/domains/*; do
        if [ -d "${D}" ]; then #If a directory
                domain=${D##*/} # Domain name
                echo ""
                echo "- In progress at the domain: "$domain;
		cd /home/$domain/public_html
                zip -r $BACKUP_DIR/source/$domain.zip ./ -q -x ./wp-content/cache/**\*
                echo "----------------------------"
        fi
done
echo "Completed";
echo '';

zip -r $BACKUP_DIR/nginx_conf.d.zip /etc/nginx/conf.d

size=$(du -sh $BACKUP_DIR | awk '{ print $1}')

echo "Starting Uploading Backup";
rclone move $BACKUP_DIR "remote:$SERVER_NAME/$TIMESTAMP" >> /var/log/rclone.log 2>&1
# Clean up
rm -rf $BACKUP_DIR
week="w"
rclone -q --min-age $number_backup$week delete "remote:$SERVER_NAME" #Remove all backups older than 2 week
rclone -q --min-age $number_backup$week rmdirs "remote:$SERVER_NAME" #Remove all empty folders older than 2 week
rclone cleanup "remote:" #Cleanup Trash
echo "Completed";
echo '';

duration=$SECONDS
echo "Information capacity and upload time : $size, $(($duration / 60)) Minutes and $(($duration % 60)) Seconds."
/etc/quicklemp/menu/drive_