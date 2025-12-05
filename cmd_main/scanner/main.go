package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/yty0v0/ReconQuiver/internal/discovery/arp_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/icmp_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/ipv6_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/netbios_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/oxid_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/tcp_host"
	"github.com/yty0v0/ReconQuiver/internal/discovery/udp_host"
	"github.com/yty0v0/ReconQuiver/internal/scan/tcp_port"
	"github.com/yty0v0/ReconQuiver/internal/scan/udp_port"
	"github.com/yty0v0/ReconQuiver/internal/scan/utils"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// Config 结构体用于存储所有的配置参数
type Config struct {
	Target          string // 目标地址 (IP或域名)
	Ports           string // 端口字符串 (如 "80,443,1000-2000")
	ScanType        string // 扫描类型
	FullScan        bool   // 是否全端口扫描标志
	CommonScan      bool   // 是否常见端口扫描标志
	Rate            int    // 扫描并发次数
	HostDiscovery   bool   // 是否进行主机发现
	CIDR            string // C段扫描
	IPRange         string // IP范围扫描
	IPList          string // IP列表扫描
	DiscoveryMode   string // 主机发现模式
	CustomRulesFile string // 自定义规则文件路径
	IPV6Host        bool   //是否进行IPV6主机探测
}

func main() {
	// 1. 解析命令行参数
	config := parseFlags()

	// 2. 验证配置参数是否合法
	if err := validateConfig(config); err != nil {
		fmt.Printf("配置错误: %v\n", err)
		return
	}

	// 3. 根据模式选择执行主机发现或端口扫描
	if config.HostDiscovery {
		// 主机发现模式
		executeHostDiscovery(config, config.Rate)
	} else {
		// 端口扫描模式
		executePortScan(config)
	}
}

// 执行端口扫描
func executePortScan(config *Config) {
	// 加载自定义规则
	if config.CustomRulesFile != "" {
		customMgr := utils.GetCustomRulesManager()
		if err := customMgr.LoadCustomRules(config.CustomRulesFile); err != nil {
			fmt.Printf("警告: 加载自定义规则失败: %v\n", err)
		} else {
			fmt.Printf("已加载自定义规则文件: %s\n", config.CustomRulesFile)
		}
	}

	// 根据配置解析出要扫描的端口列表
	ports := parsePorts(config)

	// 解析目标地址 (将域名解析为IP地址)
	ipAddress := resolveTarget(config.Target)

	// 通过扫描类型字符串调用对应扫描函数，执行扫描操作
	getScanMode(config.ScanType, ipAddress, ports, config.Rate)
}

// 执行主机发现
func executeHostDiscovery(config *Config, rate int) {
	//判断是否执行ipv6探测
	if config.IPV6Host {
		ipv6_host.Ipv6_scan()
		return //执行完直接结束
	}

	var targets []string

	// 根据不同的目标输入方式获取目标列表
	if config.CIDR != "" {
		targets = getCIDRTargets(config.CIDR)
	} else if config.IPRange != "" {
		targets = getIPRangeTargets(config.IPRange)
	} else if config.IPList != "" {
		targets = getIPListTargets(config.IPList)
	} else {
		fmt.Printf("配置错误: 必须指定一种目标输入方式 (-B, -E, 或 -L)\n")
		return
	}

	var mode string
	switch config.DiscoveryMode {
	case "T":
		mode = "TCP"
	case "TS":
		mode = "SYN"
	case "ICP":
		mode = "ICMP-PING"
	case "ICA":
		mode = "ICMP-ADDRESSMASK"
	case "ICT":
		mode = "ICMP-TIMESTAMP"
	case "U":
		mode = "UDP"
	case "N":
		mode = "NETBIOS"
	case "O":
		mode = "OXID"
	case "A":
		mode = "ARP"
	}

	fmt.Printf("开始主机发现扫描，目标数量: %d, 模式: %s\n", len(targets), mode)

	// 根据发现模式调用对应的发现函数
	switch config.DiscoveryMode {
	case "ICP":
		icmp_host.Ping(targets, rate)
	case "A":
		arp_host.Arp(targets, rate)
	case "T":
		tcp_host.Tcp_connect(targets, rate)
	case "TS":
		tcp_host.Tcp_syn(targets, rate)
	case "U":
		udp_host.Udp(targets, rate)
	case "ICT":
		icmp_host.Timestamp(targets, rate)
	case "ICA":
		icmp_host.Addressmask(targets, rate)
	case "O":
		oxid_host.Oxid(targets, rate)
	case "N":
		netbios_host.Netbios(targets, rate)
	default:
		fmt.Printf("不支持的发现模式: %s\n", config.DiscoveryMode)
	}
}

// 解析命令行参数
func parseFlags() *Config {
	config := &Config{}

	// 端口扫描参数
	flag.StringVar(&config.Target, "t", "", "目标地址 (IP/域名)")
	flag.StringVar(&config.Ports, "p", "", "指定端口 (如: 80,443,1000-2000)")
	flag.StringVar(&config.ScanType, "s", "T", "扫描类型选择: T(TCP CONNECT),TS(SYN),TA(ACK),TF(FIN),TN(NULL),U(UDP) (默认: T)")
	flag.BoolVar(&config.FullScan, "A", false, "全端口扫描 (1-65535)")
	flag.BoolVar(&config.CommonScan, "C", false, "常见端口扫描")
	flag.StringVar(&config.CustomRulesFile, "rules", "", "自定义服务识别规则文件路径") // 自定义规则参数

	// 主机发现参数
	flag.BoolVar(&config.HostDiscovery, "d", false, "启用主机发现模式")
	flag.StringVar(&config.CIDR, "B", "", "C段探测 (如: 192.168.1.0/24)")
	flag.StringVar(&config.IPRange, "E", "", "自定义IP范围探测 (如: 192.168.1.1-100)")
	flag.StringVar(&config.IPList, "L", "", "自定义IP列表探测 (逗号分隔或文件路径)")
	flag.StringVar(&config.DiscoveryMode, "m", "ICP", "主机探测模式类型选择: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP),N(NETBIOS),O(OXID) (默认: ICP)")
	flag.BoolVar(&config.IPV6Host, "6", false, "启用IPV6地址探测")

	// 公共参数
	flag.IntVar(&config.Rate, "R", 300, "并发扫描次数")

	// 自定义帮助信息显示
	flag.Usage = func() {
		fmt.Println("\n用法:\nLinux: ./reconquiver [选项]    Windows: reconquiver.exe [选项]")

		fmt.Println("\n端口扫描模式")
		fmt.Println("选项:")
		fmt.Println("  -t string        目标地址 (IP/域名)")
		fmt.Println("  -p string        指定端口 (如: 80,443,1000-2000)")
		fmt.Println("  -s string        扫描类型选择: T(TCP CONNECT),TS(SYN),TA(ACK),TF(FIN),TN(NULL),U(UDP) (默认: T)")
		fmt.Println("  -A               全端口扫描 (1-65535)")
		fmt.Println("  -C               常见端口扫描")
		fmt.Println("  -rules string 	自定义服务识别规则文件路径")

		fmt.Println("\n主机探测模式")
		fmt.Println("选项:")
		fmt.Println("  -d               启用主机发现模式")
		fmt.Println("  -B string        C段探测 (如: 192.168.1.0/24)")
		fmt.Println("  -E string        自定义IP范围探测 (如: 192.168.1.1-100)")
		fmt.Println("  -L string        自定义IP列表探测 (逗号分隔或文件路径)")
		fmt.Println("  -m string        主机探测模式类型选择: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP),N(NETBIOS),O(OXID) (默认: ICP)")
		fmt.Println("  -6               启用IPV6地址探测")

		fmt.Println("\n公共选项:")
		fmt.Println("  -R int           并发扫描次数 (默认选用合适的并发数量，可自行调整)")

		fmt.Println("\n这些模式需要使用root权限运行：TCP-SYN，TCP-ACK，TCP-FIN，TCP-NULL，UDP(主机探测)，ipv6地址探测。")

		fmt.Println("\n端口扫描常用命令:")
		fmt.Println("  ./reconquiver -t target -A               	   		TCP全端口扫描")
		fmt.Println("  sudo ./reconquiver -t target -A -s TS    	   		SYN全端口扫描")
		fmt.Println("  ./reconquiver -t target -C -s U                 		UDP常见端口扫描")
		fmt.Println("  sudo ./reconquiver -t target -C -s TA      	   		ACK常见端口扫描")
		fmt.Println("  ./reconquiver -t target -C -rules custom_rules.json 	使用自定义规则扫描")

		fmt.Println("\n主机探测常用命令:")
		fmt.Println("  ./reconquiver -d -B target -m A                 ARP模式进行C段探测")
		fmt.Println("  ./reconquiver -d -B target -m ICP               ICMP-PING模式进行C段探测")
		fmt.Println("  ./reconquiver -d -B target -m T                 TCP模式进行C段探测")
		fmt.Println("  sudo ./reconquiver -d -B target -m TS           TCP-SYN模式进行C段探测")
		fmt.Println("  sudo ./reconquiver -d -B target -m U            UDP模式进行C段探测")
		fmt.Println("  sudo ./reconquiver -d -6                        局域网内ipv6探测")
	}

	flag.Parse()
	return config
}

// 验证配置参数是否合法
func validateConfig(config *Config) error {
	//ipv6探测直接跳过校验
	if config.IPV6Host {
		if !config.HostDiscovery {
			return fmt.Errorf("ipv6探测需要启用主机发现模式 (-d)")
		}
		return nil
	}

	if config.HostDiscovery {
		// 主机发现模式验证
		targetModes := 0
		if config.CIDR != "" {
			targetModes++
		}
		if config.IPRange != "" {
			targetModes++
		}
		if config.IPList != "" {
			targetModes++
		}

		if targetModes == 0 {
			return fmt.Errorf("主机发现模式必须指定一种目标输入方式: -B, -E, 或 -L")
		}
		if targetModes > 1 {
			return fmt.Errorf("只能使用一种目标输入方式")
		}

		// 验证发现模式
		discoveryModes := []string{"ICP", "A", "T", "TS", "U", "ICT", "ICA", "O", "N"}
		validMode := false
		for _, m := range discoveryModes {
			if config.DiscoveryMode == m {
				validMode = true
				break
			}
		}
		if !validMode {
			return fmt.Errorf("不支持的发现模式: %s", config.DiscoveryMode)
		}
	} else {
		// 端口扫描模式验证
		if config.Target == "" {
			return fmt.Errorf("必须指定目标地址 (-t) 或 启用主机探测（-d）")
		}

		scanTypes := []string{"T", "TS", "TA", "TF", "TN", "U"}
		validScanType := false
		for _, t := range scanTypes {
			if config.ScanType == t {
				validScanType = true
				break
			}
		}
		if !validScanType {
			return fmt.Errorf("不支持的扫描类型: %s", config.ScanType)
		}

		scanModes := 0
		if config.FullScan {
			scanModes++
		}
		if config.CommonScan {
			scanModes++
		}
		if config.Ports != "" {
			scanModes++
		}

		if scanModes == 0 {
			return fmt.Errorf("必须指定一种扫描模式: -A(全端口) / -C(常见端口) / -p(指定端口)")
		}

		if scanModes > 1 {
			return fmt.Errorf("只能使用一种扫描模式")
		}

		if config.Rate <= 0 {
			return fmt.Errorf("并发数最小为1")
		}
	}

	return nil
}

// 解析端口配置，返回要扫描的端口列表
func parsePorts(config *Config) []int {
	var ports []int

	if config.FullScan {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		fmt.Println("扫描选择: 全端口扫描 (1-65535)")
	} else if config.CommonScan {
		ports = []int{
			20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443,
			445, 465, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 2379, 2380, 3000, 3306, 3389, 5432, 5672,
			5900, 5938, 6379, 6443, 8000, 8080, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 11211, 27017, 50000,
		}
		fmt.Println("扫描选择: 常见端口扫描")
	} else if config.Ports != "" {
		ports = parsePortString(config.Ports)
		fmt.Printf("扫描选择: 自定义端口扫描 (%s)\n", config.Ports)
	}

	return ports
}

// 解析端口字符串，支持逗号分隔和范围表示
func parsePortString(portStr string) []int {
	var ports []int
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && start > 0 && end > 0 && start <= end {
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// 解析目标地址，将域名解析为IP地址
func resolveTarget(target string) string {
	host, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		fmt.Printf("警告: 无法解析地址 %s, 将直接使用: %v\n", target, err)
		return target
	}
	return host.String()
}

// 获取扫描模式，调用对应函数执行操作
func getScanMode(scanType string, ipaddres string, port []int, rate int) {
	var mode string
	switch scanType {
	case "T":
		mode = "TCP"
	case "TS":
		mode = "SYN"
	case "TA":
		mode = "ACK"
	case "TF":
		mode = "FIN"
	case "TN":
		mode = "NULL"
	case "U":
		mode = "UDP"
	}

	fmt.Printf("开始扫描 %s, 端口数量: %d, 模式: %s\n", ipaddres, len(port), mode)

	switch scanType {
	case "T":
		tcp_port.Tcp_connect(ipaddres, port, rate)
	case "TS":
		tcp_port.Tcp_syn(ipaddres, port, rate)
	case "TA":
		tcp_port.Tcp_ack(ipaddres, port, rate)
	case "TF":
		tcp_port.Tcp_fin(ipaddres, port, rate)
	case "TN":
		tcp_port.Tcp_null(ipaddres, port, rate)
	case "U":
		udp_port.Udp(ipaddres, port, rate)
	}
}

// 主机发现相关函数

// 获取CIDR目标
func getCIDRTargets(cidr string) []string {
	var targets []string
	for i := 1; i <= 254; i++ {
		target := scanner.Ip_handle1(cidr, i)
		targets = append(targets, target)
	}

	return targets
}

// 获取IP范围目标
func getIPRangeTargets(ipRange string) []string {
	var targets []string
	start, end := scanner.Ip_handle2(ipRange)
	start1, _ := strconv.Atoi(start) //转换为int类型
	end1, _ := strconv.Atoi(end)     //转换为int类型
	for i := start1; i <= end1; i++ {
		target := scanner.Ip_handle1(ipRange, i)
		targets = append(targets, target)
	}

	return targets
}

// 获取IP列表目标
func getIPListTargets(ipList string) []string {
	var targets []string
	targets = strings.Split(ipList, ",")
	return targets
}
