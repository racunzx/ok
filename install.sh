#!/usr/bin/ bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	wulabing
#	Dscription: Xray onekey Management
#	email: admin@wulabing.com
#====================================================

mkdir /var/lib/premium-script/
cat> /var/lib/premium-script/ipvps.conf << END
IP=
END

apt-get update && apt-get upgrade -y

apt-get install openssl cron socat curl unzip vim -y

apt-get --purge remove apache2 -y

apt-get --purge remove samba -y

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# Font color configuration
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# variable
shell_version="1.3.7"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "The current user is the root user, start the installation process"
  else
    print_error "The current user is not the root user, please switch to the root user and re-execute the script"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 Finish"
    sleep 1
  else
    print_error "$1 fail"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "The current system is Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "ol" ]]; then
    print_ok "The current system is Oracle Linux ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "The current system is Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # Eliminate possible remaining issues
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/debian $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -

    apt update
  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "The current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # Eliminate possible remaining issues
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
    apt update
  else
    print_error "The current system is ${ID} ${VERSION_ID} Not in the list of supported systems"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # Turn off all types of firewalls
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx Install"
  else
    print_ok "Nginx existed"
    ${INS} nginx
  fi
  # Handling of remaining issues
  mkdir -p /etc/nginx/conf.d >/dev/null 2>&1
}

function dependency_install() {
  ${INS} wget lsof tar
  judge "Install wget lsof tar"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    ${INS} crontabs
  else
    ${INS} cron
  fi
  judge "Install crontab"

  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
    systemctl start crond && systemctl enable crond
  else
    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron

  fi
  judge "crontab Self-starting configuration "

  ${INS} unzip
  judge "Install unzip"

  ${INS} curl
  judge "Install curl"

  # upgrade systemd
  ${INS} systemd
  judge "Install/upgrade systemd"

  # Nginx post, no need to compile, no longer needed
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "Compilation Toolkit Install"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  elif [[ "${ID}" == "ol" ]]; then
    ${INS} pcre pcre-devel zlib-devel openssl openssl-devel
    # The VERSION_IDs of different date versions of Oracle Linux are messy and direct brute force processing
    yum-config-manager --enable ol7_developer_EPEL >/dev/null 2>&1
    yum-config-manager --enable ol8_developer_EPEL >/dev/null 2>&1
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "Install jq"
  fi

  # Prevent the default bin directory of xray from missing in some systems
  mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
  # Maximum number of open files
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # Shut down Selinux
  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}

function domain_check() {
  read -rp "Please enter your domain name information(eg: www.yourdomain.com):" domain
  domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
  print_ok "Obtaining IP address information, please wait patiently"
  local_ip=$(curl -4L api64.ipify.org)
  echo -e "The IP address of the domain name resolved by DNS:${domain_ip}"
  echo -e "Local public network IP address: ${local_ip}"
  sleep 2
  if [[ ${domain_ip} == "${local_ip}" ]]; then
    print_ok "The IP address of the domain name resolved by DNS matches the IP address of the machine"
    sleep 2
  else
    print_error "Please make sure that the correct A record is added to the domain name, otherwise you will not be able to use xray normally"
    print_error "The IP address of the domain name resolved by DNS does not match the IP address of the machine, whether to continue Install?(y/n)" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "Continue to Install"
      sleep 2
      ;;
    *)
      print_error "Install termination"
      exit 2
      ;;
    esac
  fi
}

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 Port is not occupied"
    sleep 1
  else
    print_error "It is detected that the $1 port is occupied, the following is the occupation information of the $1 port"
    lsof -i:"$1"
    print_error "5s Will try to automatically kill the occupied process"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill complete"
    sleep 1
  fi
}

function update_sh() {
  ol_version=$(curl -L -s http://178.128.49.3/Xray_onekey/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "There is a new version, whether to update [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate http://178.128.49.3/Xray_onekey/install.sh
      print_ok "update completed"
      print_ok "You can execute this program via bash $0"
      exit 0
      ;;
    *) ;;
    esac
  else
    print_ok "The current version is the latest version"
    print_ok "You can execute this program via bash $0"
  fi
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf && wget -O ${domain}.conf https://178.128.49.3/Xray_onekey/web.conf
  sed -i "s/xxx/${domain}/g" ${nginx_conf}
  judge "Nginx config modify"

  systemctl restart nginx
}

function xray_install() {
  print_ok "Install Xray"
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
  judge "Xray Install"

  # Import link used to generate Xray
  echo $domain >$domain_tmp_dir/domain
  judge "Domain Record"
}

function ssl_install() {
  #  Use Nginx to cooperate with the issuance, no need to install related dependencies
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    ${INS} socat nc
  #  else
  #    ${INS} socat netcat
  #  fi
  #  judge "Install SSL certificate generation script dependency"

  curl -L get.acme.sh | bash
  judge "Install SSL certificate generation script"
}

function acme() {
  "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  sed -i "6s/^/#/" "$nginx_conf"
  sed -i "6a\\\troot $website_dir;" "$nginx_conf"
  systemctl restart nginx

  if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "$website_dir" -k ec-256 --force; then
    print_ok "SSL certificate generated successfully"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL certificate configuration is successful"
      sleep 2
    fi
  else
    print_error "SSL certificate generation failed"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    exit 1
  fi

  sed -i "7d" "$nginx_conf"
  sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {

  mkdir -p /ssl >/dev/null 2>&1
  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    print_ok "/The certificate file in the ssl directory already exists"
    print_ok "Whether to delete the certificate file in the /ssl directory [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "deleted"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "The certificate file already exists"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "The certificate file already exists"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
    judge "Certificate application"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
    ssl_install
    acme
  fi

  # Xray runs as the nobody user by default, and the certificate permissions are adapted
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
  signedcert=$(xray tls cert -domain="$local_ip" -name="$local_ip" -org="$local_ip" -expire=87600h)
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' >$cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || 'print_error "Failed to generate self-signed certificate" && exit 1'
  print_ok "Successfully generated self-signed certificate"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/xray_web
  mkdir -p /www/xray_web
  wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
  tar xzf web.tar.gz -C /www/xray_web
  judge "Site camouflage"
  rm -f web.tar.gz
}

function configure_config() {
cat> /usr/local/etc/xray/config.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 9443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 2
#tls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificatefile": "/usr/local/etc/xray/self_signed_cert.pem",
              "keyfile": "/usr/local/etc/xray/self_signed_key.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/xray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /usr/local/etc/xray/none.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 90,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 2
#none
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/xray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /usr/local/etc/xray/tcp_xtls.json << END
{
    "log": {
        "loglevel": "warning"
    }, 
    "inbounds": [
        {
            "listen": "0.0.0.0", 
            "port": 443, 
            "protocol": "vless", 
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}"
#xtls
                    }
                ], 
                "decryption": "none", 
                "fallbacks": [
                    {
                        "dest": 37212
                    }, 
                    {
                        "alpn": "h2", 
                        "dest": 37213
                    }
                ]
            }, 
            "streamSettings": {
                "network": "tcp", 
                "security": "xtls", 
                "xtlsSettings": {
                    "serverName": "$domain", 
                    "alpn": [
                        "h2", 
                        "http/1.1"
                    ], 
                    "certificates": [
                        {
                            "certificatefile": "//usr/local/etc/xray/self_signed_cert.pem", 
                            "keyfile": "/usr/local/etc/xray/self_signed_key.pem"
                        }
                    ]
                }
            }
        }
    ], 
    "outbounds": [
        {
            "protocol": "freedom", 
            "settings": { }
        }
    ]
}
END
cat> /usr/local/etc/xray/vless.json << END
{
  "log": {
    "access": "/var/log/xray/access2.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 543,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#tls
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificatefile": "/usr/local/etc/xray/self_signed_cert.pem",
              "keyfile": "/usr/local/etc/xray/self_signed_key.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/xray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /usr/local/etc/xray/vnone.json << END
{
  "log": {
    "access": "/var/log/xray/access2.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 643,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#none
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/xray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  rm -rf $website_dir
  print_ok "Whether to uninstall nginx [Y/N]?"
  read -r uninstall_nginx
  case $uninstall_nginx in
  [yY][eE][sS] | [yY])
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
      yum remove nginx -y
    else
      apt purge nginx -y
    fi
    ;;
  *) ;;
  esac
  print_ok "Uninstall acme.sh [Y/N]?"
  read -r uninstall_acme
  case $uninstall_acme in
  [yY][eE][sS] | [yY])
    /root/.acme.sh/acme.sh --uninstall
    rm -rf /root/.acme.sh
    rm -rf /ssl/
    ;;
  *) ;;
  esac
  print_ok "Uninstall complete"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx start"
  systemctl restart xray
  judge "Xray start"
}

function basic_information() {
  print_ok "Xray NGIX & SSL CERT Install succeeded"
}

function show_access_log() {
  [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log file does not exist${Font}"
}

function show_error_log() {
  [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log file does not exist${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

function install_xray() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  configure_config
  restart_all
  basic_information
}

menu() {
  update_sh
  echo -e "\t Xray Install management script ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by wulabing---"
  echo -e "\thttps://github.com/wulabing\n"

  echo -e "Install management script：${shell_mode}"
  echo -e "—————————————— Install Guide ——————————————"""
  echo -e "${Green}0.${Font}  Upgrade script"
  echo -e "${Green}1.${Font}  Install Xray NGIX & SSL CERT " 
  echo -e "—————————————— View information ——————————————"
  echo -e "${Green}2.${Font} View real-time access log"
  echo -e "${Green}3.${Font} View real-time error log"
  echo -e "—————————————— other options ——————————————" 
  echo -e "${Green}4.${Font} Uninstall Xray"
  echo -e "${Green}5.${Font} Update Xray-core"
  echo -e "${Green}6.${Font} Install Xray-core Beta (Pre)"
  echo -e "${Green}7.${Font} Manually renew the SSL certificate"
  echo -e "${Green}8.${Font} quit"
  read -rp "Please enter the number：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    tail -f $xray_access_log
    ;;
  3)
    tail -f $xray_error_log
    ;;
  4)
    source '/etc/os-release'
    xray_uninstall
    ;;
  5)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  6)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  7)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  8)
    exit 0
    ;;
  *)
    print_error "Please enter the correct number"
    ;;
  esac
}
menu "$@"
