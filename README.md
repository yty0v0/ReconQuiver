# ReconQuiver - "侦察袖箭"，一款轻量化端口扫描和主机探测工具

## 简介
基于Go编写的轻量化端口扫描和主机探测工具，支持多种扫描/探测技术。
各种模式和方法可以自由切换，使用简单，代码通俗易懂，并附有详细注释，方便基于该工具进行再次改进和功能添加。
同时支持Windows，Linux系统。

### 端口扫描
包括四种扫描方法：全端口扫描，常见端口扫描，自定义端口扫描，自定义端口范围扫描。

包括六种扫描模式：TCP-CONNECT，TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP。

包括对开放服务的智能指纹识别，支持自定义指纹识别规则，用户可按需自行扩展。

### 存活主机探测
包括三种探测方法：C段探测，自定义主机范围探测，自定义主机列表探测。

包括九种探测模式：ARP，ICMP-PING，ICMP-ADDRESSMASK，ICMP-TIMESTAMP，TCP-CONNECT，TCP-SYN，UDP，OXID，NETBIOS。

包括对主机MAC地址，主机信息(所属厂商，类型，操作系统，主机名)，主机状态，主机存活原因的获取

包括IPV6地址的探测

## 安装
### Linux安装
直接下载zip压缩包，放到Linux上解压
```
unzip ReconQuiver-main.zip
```
进入项目目录并编译
```
cd ReconQuiver-main
go build -o reconquiver cmd_main/scanner/main.go
```
运行程序查看帮助信息，如果显示帮助信息说明安装成功
```
./reconquiver -h
```
### Windows安装
解压以后找到ReconQuiver-main所在目录，通过cmd打开命令行，进入目录并编译
```
cd ReconQuiver-main
go build -o reconquiver.exe cmd_main/scanner/main.go
```
运行程序查看帮助信息，如果显示帮助信息说明安装成功
```
reconquiver.exe -h
```

## 使用说明

### 端口扫描
```
选项:
-t string    目标地址 (IP/域名)
-p string    指定端口 (如: 80,443,1000-2000)
-s string    扫描类型选择: T(TCP CONNECT),TS(SYN),TA(ACK),TF(FIN),TN(NULL),U(UDP) (默认: T)
-A           全端口扫描 (1-65535)
-C           常见端口扫描

端口扫描常用命令:
./reconquiver -t traget -A                        TCP全端口扫描
sudo ./reconquiver -t target -A -s TS             SYN全端口扫描
./reconquiver -t target -C -s U                   UDP常见端口扫描
sudo ./reconquiver -t target -C -s TA             ACK常见端口扫描
```

### 主机探测
```
选项:
-d           启用主机发现模式
-B string    C段探测 (如: 192.168.1.0/24)
-E string    自定义IP范围探测 (如: 192.168.1.1-100)
-L           自定义IP列表探测 (逗号分隔或文件路径)
-m string    主机探测模式类型选择: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP),N(NETBIOS),O(OXID) (默认: ICP)
-6           启用IPV6地址探测

主机探测常用命令:
./reconquiver -d -B traget -m A                   ARP模式进行C段探测
sudo ./reconquiver -d -B traget -m ICP            ICMP-PING模式进行C段探测
./reconquiver -d -B traget -m T                   TCP模式进行C段探测
sudo ./reconquiver -d -B traget -m TS             TCP-SYN模式进行C段探测
sudo ./reconquiver -d -B traget -m U              UDP模式进行C段探测
sudo ./reconquiver -d -6                          局域网内ipv6探测
```

### 并发设置
```
-R int       并发扫描次数 (默认选用合适的并发数量，可自行调整)

示例: 
sudo ./reconquiver -t target -A -s TS -R 500          并发500
sudo ./reconquiver -d -B traget -m ICP -R 2000        并发2000
```

### 自定义服务指纹识别规则
默认的自定义规则识别文件是ReconQuiver目录下的custom_rules.json，可以根据自己想要的规则进行更改和扩展。也可以指定不存在的文件，会自动生成。
```
{
  "rules": [
    {
      "name": "识别数据的名称，随便写，能看懂就行",  
      "ports": [识别数据的指定端口，可以写多个，如果为空则所有端口适用],
      "protocol": "探测的协议类型，tcp/udp二选一",
      "data": "发送的探测数据，十六进制数据或字符串，拿ai生成一下你想要的",
      "send_first": 是否发送数据，true/false，一般为true，除非你的探测数据设置为空,
      "match": [
        "匹配规则1",
        "匹配规则2",
        "匹配规则3"
        ......
      ],
      "is_binary": [
        匹配规则1是否为二进制数据,
        匹配规则2是否为二进制数据,
        匹配规则3是否为二进制数据
        ......
      ],
      "service": "识别的服务名称"
    }
  ]
}
```
要把内容都按格式写才能识别成功，字段名也需要一样，都是小写。
```
格式:

{
  "rules": [
    {
      自定义规则1
    },
    {
      自定义规则2  
    }
  ]
}
```
下面给了两个示例
```
{
  "rules": [
    {
      "name": "MySQLAuth",  
      "ports": [3306],
      "protocol": "tcp",
      "data": "85a6ff0100000001210000000000000000000000000000000000000000000000726f6f740000",
      "send_first": true,
      "match": [
        "\\\\x00\\\\x00\\\\x01\\\\xff",
        "Host '.*' is not allowed",
        "Access denied for user"
      ],
      "is_binary": [
        true,
        false,
        false
      ],
      "service": "mysql"
    },
    {
      "name": "CustomHTTP",
      "ports": [8080, 8081],
      "protocol": "tcp",
      "data": "GET / HTTP/1.1\\r\\nHost: localhost\\r\\nUser-Agent: CustomScanner\\r\\n\\r\\n",
      "send_first": true,
      "match": [
        "HTTP/[0-9.]+ ([0-9]+).*Server: ([^\\r\\n]+)"
      ],
      "is_binary": [
        false
      ],
      "service": "http"
    }
  ]
}
```
通过如下的方式指定自定义规则文件，这个功能只有端口扫描时可以用
```
-rules string 	自定义服务识别规则文件路径

示例:
./reconquiver -t traget -A  -rules custom_rules.json
```

## 注意事项
(1) 以下模式需要使用root权限运行：
TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP(主机探测)，ICMP-PING，ICMP-ADDRESSMASK，ICMP-TIMESTAMP。

(2) 并发数量设置的大小可能会影响扫描/探测结果
