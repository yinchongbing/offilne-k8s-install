
# 制作离线yum repo



| hostname | ip            | 网络           |
| -------- | ------------- | -------------- |
| centosA  | xxx.xxx.xxx.a | 需要连接互联网 |
| centosB  | xxx.xxx.xxx.b | 内网           |



## 1.制作

在有网的centosA服务器上执行。

```shell
#yum工具安装
yum install -y createrepo yum-utils

#创建目录
mkdir /opt/offline-install/rpm-repo

#初始化yum源
createrepo  /opt/offline-install/rpm-repo

#下载依赖包
repotrack docker-ce-19.03.15
repotrack ipvsadm-1.27
repotrack kubeadm-1.18.20
repotrack kubelet-1.18.20
repotrack kubectl-1.18.20
repotrack keepalived-1.3.5
repotrack haproxy-1.5.18
repotrack ntp-4.2.6p5
repotrack ntpdate-4.2.6p5
repotrack ipset-7.1

#下载完后更新
createrepo --update /opt/offline-install/rpm-repo

# tar打包
cd /opt
tar czvf offline-install.tar.gz offline-install/
```



## 2.使用

从centosA服务器拷贝offline-install.tar.gz压缩包到centosB服务器/opt目录下。

在centosB服务器上执行。

```shell
#!/bin/bash
###############################搭建私有yum源#################################
#切换目录
cd /opt

#解压/opt/offline-install.tar.gz
tar zxvf offline-install.tar.gz

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

#服务端更新后客户端清除缓存
yum clean all
yum makecache
```

