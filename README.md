# offilne-k8s-install
离线k8s部署，仅仅适用于k8s 1.18.20版本部署



服务器版本：

操作系统：建议CentOS Linux release 7.9.2009 (Core)

内核版本: 建议3.10.0-1160.71.1.el7.x86_64

k8s版本: 1.18.20

## 1.服务器规划

| ip            | hostname     | 网卡 |
| ------------- | ------------ | ---- |
| xxx.xxx.xxx.a | k8s-master01 | eno1 |
| xxx.xxx.xxx.b | k8s-master02 | eno1 |
| xxx.xxx.xxx.c | k8s-master03 | eno1 |
| xxx.xxx.xxx.d | k8s-slave01  | eno1 |
| xxx.xxx.xxx.e | k8s-slave02  | eno1 |

vip: xxx.xxx.xxx.f

## 2.下载离线包

下载离线包到k8s-master01服务器/opt下

离线包链接：https://pan.baidu.com/s/1TXmwwRQK9KttHHwwKSLdCQ 
提取码：vavd



## 3.配置本地yum repo

配置文件备份

```shell
cd /etc/yum.repos.d/
rename .repo .repo.bak *
```

 创建配置(所有kubernets相关的服务器都需要配置yum repo源)

```shell
#配置Yum源文件
cd /etc/yum.repos.d
rename .repo .repo.bak *

cat >> /etc/yum.repos.d/inspur-ici-repo.repo << EOF
[inspur-ici-local]
name=CentOS-Local
baseurl=file:///opt/offline-install/rpm-repo
gpgcheck=0
enabled=1
EOF
```

服务端更新后客户端清除缓存

```shell
yum clean all
yum makecache
```


## 4.kubernetes服务器配置

每台Kubernetes服务器，包括Master、slave节点初始化内容如下：

### 4.1修改主机名

分别对每台主机执行如下操作

```shell
hostnamectl set-hostname k8s-master01
hostnamectl set-hostname k8s-master02
hostnamectl set-hostname k8s-master03
hostnamectl set-hostname k8s-slave01
hostnamectl set-hostname k8s-slave01
```



### 4.2更新hosts

在主机的/etc/hosts文件中添加如下内容：

```shell
cat >> /data01/hosts << EOF
#k8s cluster
xxx.xxx.xxx.a k8s-master01
xxx.xxx.xxx.b k8s-master02
xxx.xxx.xxx.c k8s-master03
xxx.xxx.xxx.d k8s-slave01
xxx.xxx.xxx.e k8s-slave02
EOF
```

配置完成后测试

```shell
ping k8s-slave01
```


### 4.3禁用selinux

selinux是linux系统下的一个安全服务，如果不关闭它，在安装集群中会产生各种各样的奇葩问题 

编辑 /etc/selinux/config 文件，修改SELINUX的值为disable 

注意修改完毕之后需要重启linux服务 

```shell
vi /etc/selinux/config
```

修改内容如下

SELINUX=disabled 

修改完成后重启服务器

```shell
reboot
```



### 4.4关闭缓存

K8s 1.8开始要求关闭系统的swap，如果不关闭，默认情况下kubelet将无法启动

```shell
swapoff -a && sysctl -w vm.swappiness=0
```

修改 /etc/fstab，注释swap的自动挂载

```shell
vim /etc/fstab
```

验证是否生效(swap为0)

```shell
free 
```



### 4.5调整内核参数

```shell
cat > /etc/sysctl.d/kubernetes.conf <<EOF
# 开启网桥模式(必须)
net.bridge.bridge-nf-call-iptables = 1
# 开启网桥模式(必须)
net.bridge.bridge-nf-call-ip6tables = 1
# 关闭IPv6协议(必须)
net.ipv6.conf.all.disable_ipv6 = 1
# 转发模式(默认开启)
net.ipv4.ip_forward = 1
# 开启OOM(默认开启)
vm.panic_on_oom=0
#禁止使用swap空间
vm.swappiness = 0
# 不检查物理内存是否够用
vm.overcommit_memory=1
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
# 设置文件句柄数量
fs.file-max = 52706963
# 设置文件的最大打开数量
fs.nr_open = 52706963
net.netfilter.nf_conntrack_max = 2310720
net.netfilter.nf_conntrack_max=2310720
EOF
```

加载conntrack，否则运行如下命令可能会出现sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_max: No such file or directory错误
modprobe ip_conntrack

使内核参数配置文件生效

```shell
sysctl -p
```

之前是ulimit -n 65535那样设置，不过貌似只是当前环境有效果，重启服务器的话，又失效了。。。今天无意找到一个设置的方法，可以永久设置ulimit的参数。

打开/etc/security/limits.conf添加

```shell
cat >> /etc/security/limits.conf << EOF
* hard nofile 1048576
* soft nofile 1048576
* hard nproc 1048576
* soft nproc 1048576
EOF
```

 

### 4.6设置时钟同步

所有服务器安装ntp服务，命令如下：

```shell
yum install -y ntp
```

设置为开机启动

```shell
systemctl enable ntpd
systemctl start ntpd 
```

Server端配置：

```shell
vim /etc/ntp.conf
```

配置ntp配置文件，注释上面4个server行，添加如下2个ntp时间服务器ip，然后重启ntpd服务即可。

server 主时间服务器 preferserver



查看ntp服务状态

```shell
systemctl status ntpd 
ntpq -p 
ntpdate -q ip  
```



### 4.7关闭防火墙

kubernetes和docker 在运行的中会产生大量的iptables规则

为了不让系统规则跟它们混淆，直接关闭系统的规则

```shell
systemctl stop firewalld
systemctl disable firewalld
```



### 4.8开启IPVS

由于Kubernets在使用Service的过程中需要用到iptables或者是ipvs，ipvs整体上比iptables的转发效率要高，因此这里我们直接部署ipvs

\#安装 ipset 及 ipvsadm

```shell
yum install -y ipset ipvsadm
```

添加需要加载的模块，ipvs作为kube-proxy的转发机制，开启ipvs模块支持

```shell
cat > /etc/ipvs.modules << EOF
#!/bin/bash
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack
EOF
```

授权、运行、检查是否加载

```shell
chmod +x /etc/ipvs.modules && bash /etc/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack_ipv4
```

 

## 5.配置高可用keepalived+haproxy

安装keepalived+haproxy(需要在k8s-master01,k8s-master02,k8s-master03)

```shell
yum install -y keepalived-1.3.5 haproxy-1.5.18
```

### keepalive



k8s-master01上
vim /etc/keepalived/keepalived.conf

```conf
! Configuration File for keepalived

global_defs {
   notification_email {
     acassen@firewall.loc
     failover@firewall.loc
     sysadmin@firewall.loc
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 192.168.200.1
   smtp_connect_timeout 30
   router_id LVS_DEVEL
   vrrp_skip_check_adv_addr
#   vrrp_strict
   vrrp_garp_interval 0
   vrrp_gna_interval 0
}
vrrp_instance VI_1 {
    state BACKUP
    interface eno1     #本机网卡名称(必须修改)
    virtual_router_id 51
    priority 80
    advert_int 1
    unicast_src_ip xxx.xxx.xxx.a  #本机ip(必须修改)
    unicast_peer {
      xxx.xxx.xxx.b               #对端ip(必须修改)
      xxx.xxx.xxx.c
    }
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {           #虚拟ip(必须修改)
        xxx.xxx.xxx.f
    }
}
```



k8s-master02上
vim /etc/keepalived/keepalived.conf

```conf
! Configuration File for keepalived

global_defs {
   notification_email {
     acassen@firewall.loc
     failover@firewall.loc
     sysadmin@firewall.loc
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 192.168.200.1
   smtp_connect_timeout 30
   router_id LVS_DEVEL
   vrrp_skip_check_adv_addr
#   vrrp_strict
   vrrp_garp_interval 0
   vrrp_gna_interval 0
}

vrrp_instance VI_1 {
    state MASTER
    interface eno1         #本机网卡名称(必须修改)
    virtual_router_id 51
    priority 100
    advert_int 1
    unicast_src_ip xxx.xxx.xxx.b     #本机ip(必须修改)
    unicast_peer {
      xxx.xxx.xxx.a                  #对端ip(必须修改)
      xxx.xxx.xxx.c
    }
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {               #虚拟ip(必须修改)
        xxx.xxx.xxx.f
    }
}
```



k8s-master03上
vim /etc/keepalived/keepalived.conf

```conf
! Configuration File for keepalived

global_defs {
   notification_email {
     acassen@firewall.loc
     failover@firewall.loc
     sysadmin@firewall.loc
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 192.168.200.1
   smtp_connect_timeout 30
   router_id LVS_DEVEL
   vrrp_skip_check_adv_addr
#   vrrp_strict
   vrrp_garp_interval 0
   vrrp_gna_interval 0
}

vrrp_instance VI_1 {
    state BACKUP
    interface eno1                #本机网卡名称(必须修改)
    virtual_router_id 51
    priority 80
    advert_int 1
    unicast_src_ip xxx.xxx.xxx.c   #本机ip(必须修改)
    unicast_peer {
      xxx.xxx.xxx.a                 #对端ip(必须修改)
      xxx.xxx.xxx.b
    }
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {              #虚拟ip(必须修改)
        xxx.xxx.xxx.f
    }
}
```



### haproxy

在k8s-master01,k8s-master02,k8s-master03上，三台配置一样

```conf
#---------------------------------------------------------------------
# Example configuration for a possible web application.  See the
# full configuration options online.
#
#   http://haproxy.1wt.eu/download/1.4/doc/configuration.txt
#
#---------------------------------------------------------------------

#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # to have these messages end up in /var/log/haproxy.log you will
    # need to:
    #
    # 1) configure syslog to accept network log events.  This is done
    #    by adding the '-r' option to the SYSLOGD_OPTIONS in
    #    /etc/sysconfig/syslog
    #
    # 2) configure local2 events to go to the /var/log/haproxy.log
    #   file. A line like the following can be added to
    #   /etc/sysconfig/syslog
    #
    #    local2.*                       /var/log/haproxy.log
    #
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

#---------------------------------------------------------------------
# main frontend which proxys to the backends
#---------------------------------------------------------------------
frontend  main *:5000
    acl url_static       path_beg       -i /static /images /javascript /stylesheets
    acl url_static       path_end       -i .jpg .gif .png .css .js

    use_backend static          if url_static
    default_backend             app

frontend kubernetes-master
    bind *:8443
    mode tcp
    default_backend kubernetes-master
#---------------------------------------------------------------------
# static backend for serving up images, stylesheets and such
#---------------------------------------------------------------------
backend static
    balance     roundrobin
    server      static 127.0.0.1:4331 check

#---------------------------------------------------------------------
# round robin balancing between the various backends
#---------------------------------------------------------------------
backend app
    balance     roundrobin
    server  app1 127.0.0.1:5001 check
    server  app2 127.0.0.1:5002 check
    server  app3 127.0.0.1:5003 check
    server  app4 127.0.0.1:5004 check

backend kubernetes-master
    mode tcp
    balance roundrobin
    server k8s-master01 xxx.xxx.xxx.a:6443 check inter 1s fall 1 rise 1
    server k8s-master02 xxx.xxx.xxx.b:6443 check inter 1s fall 1 rise 1
    server k8s-master03 xxx.xxx.xxx.c:6443 check inter 1s fall 1 rise 1
```



### 重启服务

```shell
systemctl daemon-reload && systemctl restart haproxy keepalive
```



## 6.安装Docker

安装Docker(所有kubernets相关的服务器都需要安装docker服务)

```shell
yum -y install docker-ce-19.03.15
```

创建或修改/etc/docker/daemon.json

data-root: docker数据盘的目录，建议此目录下docker可用磁盘容量大于1TB

exec-opts: 设置cgroup驱动为systemd，和kuberbetes保持一致

```shell
mkdir -p /etc/docker/ 
cat > /etc/docker/daemon.json <<EOF 
{
 "insecure-registries": [
  ""
 ],
 "exec-opts": ["native.cgroupdriver=systemd"],
 "data-root": "/data/docker-data/default"
}
EOF
```

设置开机启动

```shell
systemctl enable docker --now
```

重启 docker

```shell
systemctl restart docker
```

 验证

```shell
docker info | grep Cgroup
```

 加载镜像到本地(需要在kubernetes所有节点执行)

```shell
docker load -i /opt/offline-install/images/k8s-images.tar.gz
```



## 7.安装Kubeadm,kubelet,kubectl

安装工具

```shell
yum install -y kubelet-1.18.20 kubeadm-1.18.20 kubectl-1.18.20
systemctl enable kubelet
```



覆盖kubeadm命令行(kubernetes所有节点都需要覆盖)

```shell
cp /data01/offline-install/kubeadm /usr/bin/kubeadm
chmod +x /usr/bin/kubeadm
```



## 8.kubeadm初始化集群

```shell
#1.初始化第一个master节点(仅仅需要在k8s-master01节点执行)
kubeadm init --config kubeadm.yaml --upload-certs

# 注意: init成功后有复制配置文件到~/.kube/的命令输出，按照输出执行完后即可使用kubectl命令.

#2.记录初始化命令返回值，通过kubeadm join命令加入剩余的master和node(这里只记录的命令，是本次试验的输出，实际部署时候会在kubeadm init命令执行后输出)
#加入master命令,需要在k8s-master02,k8s-master03上执行(此命令需要的值可以通过kubeadm查询出来)：
kubeadm join xxx.xxx.xxx.f:8443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:45e67875461e25463f6813a4232165e9c657873be1f93d9884518c99701e4704 --control-plane --certificate-key 4490e970e5a7d755ae68056c757caa936c25c191f66e324f2c370d6b567db524
#加入node命令,需要在k8s-slave01,k8s-slave02上执行：
kubeadm join xxx.xxx.xxx.f:8443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:45e67875461e25463f6813a4232165e9c657873be1f93d9884518c99701e4704

#3.如果kubeadm join 命令因为时间过长导致token过期，可以使用以下命令再次打印出来
# master
kubeadm token create --print-join-command --control-plane

# slave
kubeadm token create --print-join-command
```

kubeadm.yaml配置文件如下

kubeadm.yaml

```yaml
#kubeadm初始化文件kubeadm.yaml可以通过kubeadm config print init-defaults -h获得，需要加以修改。
apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: xxx.xxx.xxx.a            #本机ip，也就是k8s-master01的ip(必须修改)
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: k8s-master01
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd                  #etcd数据持久化目录，建议修改，默认/var/lib/etcd
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
kind: ClusterConfiguration
kubernetesVersion: v1.18.20
controlPlaneEndpoint: xxx.xxx.xxx.f:8443     #高可用虚拟ip，使用前用ping测试呢个否访问，不能ping通检查第5节(必须修改)
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12              #k8s服务网段，可自定义，避免与本地网段和docker网段冲突
  podSubnet: 10.244.0.0/16                 #k8s pod网段，可自定义，避免与本地网段和docker网段冲突
scheduler: {}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs                                 #kube-proxy代理模式，建议ipvs
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
```



## 9.部署calico

更改描述文件
vim /opt/offline-install/calico /calico-v3.18.yaml

```yaml
            # no effect. This should fall within `--cluster-cidr`.这里指定pod网段(3680行)
            - name: CALICO_IPV4POOL_CIDR
              value: "10.244.0.0/16"
              
  # Configure the interface to use.这里指定网卡名称(16行)
  calico_interface: "interface=eno1"
```



部署calico(只需要在k8s-master01执行)

```shell
kubectl apply -f /opt/offline-install/calico /calico-v3.18.yaml
```



## 10.检查集群状态

以下检查命令在k8s-master01下执行即可

```shell
# 集群节点均为Ready状态，表示正常
kubectl get no 

# pod全部running，表示正常
kubectl get po -n kube-system

# 集群证书期限为100年，表示正常
[root@k8s-master01]# kubeadm alpha certs check-expiration
[check-expiration] Reading configuration from the cluster...
[check-expiration] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -oyaml'

CERTIFICATE                EXPIRES                  RESIDUAL TIME   CERTIFICATE AUTHORITY   EXTERNALLY MANAGED
admin.conf                 Aug 03, 2121 02:00 UTC   99y                                     no      
apiserver                  Aug 03, 2121 02:00 UTC   99y             ca                      no      
apiserver-kubelet-client   Aug 03, 2121 02:00 UTC   99y             ca                      no      
controller-manager.conf    Aug 03, 2121 02:00 UTC   99y                                     no      
front-proxy-client         Aug 03, 2121 02:00 UTC   99y             front-proxy-ca          no      
scheduler.conf             Aug 03, 2121 02:00 UTC   99y                                     no      

CERTIFICATE AUTHORITY   EXPIRES                  RESIDUAL TIME   EXTERNALLY MANAGED
ca                      Aug 03, 2121 02:00 UTC   99y             no      
front-proxy-ca          Aug 03, 2121 02:00 UTC   99y             no   
```

