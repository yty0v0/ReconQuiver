package ipv6_host

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/context"
)

const timeoutSeconds = 5

type DiscoveredHost struct {
	IP  string
	MAC string
}

type IPv6Discoverer struct {
	timeout time.Duration
}

func NewIPv6Discoverer(timeout time.Duration) *IPv6Discoverer {
	return &IPv6Discoverer{timeout: timeout}
}

func (d *IPv6Discoverer) runMulticastPing() {
	addresses := []string{"ff02::1", "ff02::2", "ff02::1:ff00:0"}

	for _, addr := range addresses {
		var cmd *exec.Cmd

		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("ping", "-6", "-n", "2", "-w", "1500", addr)
		case "darwin": // macOS
			cmd = exec.Command("ping6", "-c", "2", "-W", "2", addr)
		default: // Linux和其他Unix系统
			cmd = exec.Command("ping6", "-c", "2", "-W", "1", addr)
		}

		go cmd.Run()
		log.Printf("Sent multicast ping to %s on %s", addr, runtime.GOOS)
		time.Sleep(300 * time.Millisecond)
	}
}

func (d *IPv6Discoverer) isValidMAC(mac string) bool {
	// 统一格式
	mac = strings.ReplaceAll(strings.ToLower(mac), "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")

	if strings.Contains(mac, "00:00:00:00:00:00") || strings.Contains(mac, "ff:ff:ff:ff:ff:ff") {
		return false
	}

	//通过:分割以后总切片长度必须是6
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}

	for _, part := range parts {
		//分割成切片后每块长度必须是2
		if len(part) != 2 {
			return false
		}
		//检查每一位是否合法
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				return false
			}
		}
	}
	return true
}

// 查询邻居表
func (d *IPv6Discoverer) getNeighbors() []DiscoveredHost {
	var output []byte
	var err error

	switch runtime.GOOS {
	case "windows":
		output, err = exec.Command("netsh", "interface", "ipv6", "show", "neighbors").Output()
	case "darwin": // macOS
		output, err = exec.Command("ndp", "-an").Output()
	default: // Linux
		output, err = exec.Command("ip", "-6", "neighbor", "show").Output()
	}

	if err != nil {
		log.Printf("Failed to get neighbors on %s: %v", runtime.GOOS, err)
		return nil
	}

	//处理查询的结果
	return d.parseNeighbors(string(output))
}

// 解析系统邻居表输出，将不同系统的邻居信息统一转换为结构化的设备列表
func (d *IPv6Discoverer) parseNeighbors(output string) []DiscoveredHost {
	// 使用MAC地址作为key，存储最佳地址选择
	hostsByMAC := make(map[string]DiscoveredHost)

	//将字符串按换行符分割成切片
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line) //去掉字符串开头和结尾的所有空白字符
		if line == "" {
			continue
		}

		var ip, mac string
		var valid bool

		//获取当前操作系统的名称，并选择合适的方法
		switch runtime.GOOS {
		case "windows":
			ip, mac, valid = d.parseWindowsLine(line)
		case "darwin":
			ip, mac, valid = d.parseMacOSLine(line)
		default:
			ip, mac, valid = d.parseLinuxLine(line)
		}

		//检查是否解析成功，MAC地址是否有效，IP是否有效
		if valid && d.isValidMAC(mac) && d.isValidIP(ip) {
			macNormalized := strings.ReplaceAll(strings.ToLower(mac), "-", ":")
			macNormalized = strings.ReplaceAll(macNormalized, ".", ":")

			currentHost := DiscoveredHost{IP: ip, MAC: macNormalized}
			currentIP := net.ParseIP(ip)

			// 检查是否已经存在这个MAC的记录
			if existingHost, exists := hostsByMAC[macNormalized]; exists {
				existingIP := net.ParseIP(existingHost.IP)

				// 地址选择优先级：全局地址 > 重要链路本地地址 > 其他链路本地地址
				if d.shouldReplace(existingIP, currentIP) {
					hostsByMAC[macNormalized] = currentHost
				}
			} else {
				// 新设备，直接添加
				hostsByMAC[macNormalized] = currentHost
			}
		}
	}

	// 转换为切片
	var hosts []DiscoveredHost
	for _, host := range hostsByMAC {
		hosts = append(hosts, host)
	}
	return hosts
}

// shouldReplace 判断是否应该用新地址替换现有地址
func (d *IPv6Discoverer) shouldReplace(existing, current net.IP) bool {
	// 规则1: 全局地址优先于链路本地地址
	if existing.IsLinkLocalUnicast() && current.IsGlobalUnicast() {
		return true
	}

	// 规则2: 重要的链路本地地址优先于普通链路本地地址
	if existing.IsLinkLocalUnicast() && current.IsLinkLocalUnicast() {
		existingStr := existing.String()
		currentStr := current.String()

		// fe80::1 (路由器) 是最重要的链路本地地址
		if existingStr != "fe80::1" && currentStr == "fe80::1" {
			return true
		}

		// 包含EUI-64格式的地址优先（更规范）
		existingHasEUI64 := strings.Contains(existingStr, "ff:fe") || strings.Contains(existingStr, "fffe")
		currentHasEUI64 := strings.Contains(currentStr, "ff:fe") || strings.Contains(currentStr, "fffe")

		if !existingHasEUI64 && currentHasEUI64 {
			return true
		}
	}

	// 规则3: 相同类型的情况下，保持第一个发现的地址
	return false
}

func (d *IPv6Discoverer) parseWindowsLine(line string) (string, string, bool) {
	if strings.Contains(line, "接口") || strings.Contains(line, "Interface") ||
		strings.HasPrefix(line, "---") {
		return "", "", false
	}

	fields := strings.Fields(line)
	if len(fields) >= 3 {
		ip, mac, state := fields[0], fields[1], fields[2]
		//过滤掉无效的状态
		if state != "incomplete" && state != "failed" && state != "无法访问" {
			return ip, mac, true
		}
	}
	return "", "", false
}

func (d *IPv6Discoverer) parseLinuxLine(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) >= 6 {
		ip := fields[0]
		mac := fields[4]
		state := fields[len(fields)-1]
		// Linux邻居状态: REACHABLE, STALE, DELAY, PROBE等
		if state == "REACHABLE" || state == "STALE" || state == "DELAY" {
			return ip, mac, true
		}
	}
	return "", "", false
}

func (d *IPv6Discoverer) parseMacOSLine(line string) (string, string, bool) {
	// macOS ndp输出格式: 192.168.1.1 at 00:11:22:33:44:55 on en0 ifscope permanent
	fields := strings.Fields(line)
	if len(fields) >= 4 && fields[1] == "at" {
		ip := fields[0]
		mac := fields[2]
		return ip, mac, true
	}
	return "", "", false
}

func (d *IPv6Discoverer) isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil &&
		!parsed.IsMulticast() &&
		!strings.Contains(ip, "ff02::1:ff") &&
		(parsed.IsLinkLocalUnicast() || parsed.IsGlobalUnicast())
}

// 判断邻居表查询的每个ipv6地址是否可达
func (d *IPv6Discoverer) pingHost(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// 如果是全局地址或不带作用域的fe80地址
	if !parsed.IsLinkLocalUnicast() {
		return d.pingHostSingle(ip, "")
	}

	// 对于fe80::地址，如果已经有作用域，直接使用
	if strings.Contains(ip, "%") {
		return d.pingHostSingle(ip, "")
	}

	// 获取所有可用的接口
	interfaces := d.getActiveInterfaces()
	if len(interfaces) == 0 {
		// 没有可用接口，使用宽松策略
		return d.shouldAcceptDespitePingFailure(ip)
	}

	// 并行尝试所有接口
	results := make(chan bool, len(interfaces))
	sem := make(chan struct{}, 4) // 限制并发数

	for _, iface := range interfaces {
		sem <- struct{}{}
		go func(interfaceName string) {
			defer func() { <-sem }()

			if d.pingHostSingle(ip, interfaceName) {
				results <- true
			} else {
				results <- false
			}
		}(iface.Name)
	}

	// 等待所有goroutine完成
	for i := 0; i < len(interfaces); i++ {
		if <-results {
			// 只要有一个接口ping成功，就认为可达
			return true
		}
	}

	// 所有接口都失败，使用宽松策略
	return d.shouldAcceptDespitePingFailure(ip)
}

// pingHostSingle 使用特定接口进行ping测试（辅助函数）
func (d *IPv6Discoverer) pingHostSingle(ip, interfaceName string) bool {
	var cmd *exec.Cmd
	target := ip

	// 如果是链路本地地址且未指定作用域，添加接口作用域
	if strings.HasPrefix(ip, "fe80::") && !strings.Contains(ip, "%") && interfaceName != "" {
		target = ip + "%" + interfaceName
	}

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-6", "-n", "1", "-w", "500", target)
	case "darwin":
		cmd = exec.Command("ping6", "-c", "1", "-W", "1", target)
	default: // Linux和其他Unix系统
		// 尝试ping6，如果不存在则使用ping -6
		if _, err := exec.LookPath("ping6"); err == nil {
			cmd = exec.Command("ping6", "-c", "1", "-W", "1", target)
		} else {
			cmd = exec.Command("ping", "-6", "-c", "1", "-W", "1", target)
		}
	}

	// 设置超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

	err := cmd.Run()
	if err == nil {
		return true
	}

	// 即使是单个接口ping失败，也返回false，让主函数处理宽松策略
	return false
}

// shouldAcceptDespitePingFailure 宽松策略：即使ping失败也接受某些地址
func (d *IPv6Discoverer) shouldAcceptDespitePingFailure(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// 1. 全局单播地址
	if parsed.IsGlobalUnicast() {
		return true
	}

	// 2. 重要的链路本地地址
	if ip == "fe80::1" {
		return true // 常见路由器地址
	}

	// 3. EUI-64格式地址（根据MAC地址生成）
	ipStr := parsed.String()
	if strings.Contains(ipStr, "ff:fe") || strings.Contains(ipStr, "fffe") {
		return true // 很可能是真实设备
	}

	// 4. 特定模式的链路本地地址
	if parsed.IsLinkLocalUnicast() {
		// 检查是否是扩展的EUI-64格式
		ipLower := strings.ToLower(ipStr)
		// 匹配格式：fe80::xxxx:xxff:fexx:xxxx
		if strings.Contains(ipLower, "ff:fe") {
			return true
		}

		// 长度较长的fe80地址更可能是有效地址
		if len(ipStr) >= 20 { // 调整阈值
			return true
		}
	}

	return false
}

// getActiveInterfaces 获取所有活跃的网络接口（辅助函数）
func (d *IPv6Discoverer) getActiveInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var activeInterfaces []net.Interface

	for _, iface := range ifaces {
		// 检查接口是否启用且非回环
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 检查接口是否有任何IP地址
		hasIP := false
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					// 接受任何有效的IP地址
					if ipnet.IP.To4() != nil ||
						ipnet.IP.IsGlobalUnicast() ||
						ipnet.IP.IsLinkLocalUnicast() ||
						!ipnet.IP.IsMulticast() && !ipnet.IP.IsUnspecified() {
						hasIP = true
						break
					}
				}
			}
		}

		if hasIP {
			activeInterfaces = append(activeInterfaces, iface)
		}
	}

	return activeInterfaces
}

// 调用邻居表查询并处理查询数据
func (d *IPv6Discoverer) getActiveHosts() []DiscoveredHost {
	//查询邻居表
	neighbors := d.getNeighbors()

	if len(neighbors) == 0 {
		return nil
	}

	results := make(chan DiscoveredHost, len(neighbors))
	sem := make(chan struct{}, 8)

	for _, host := range neighbors {
		sem <- struct{}{}
		go func(h DiscoveredHost) {
			defer func() { <-sem }()

			//检查地址是否通
			if d.pingHost(h.IP) {
				results <- h //// 通道操作是线程安全的，如果用切片要加锁避免并发冲突
			}
		}(host)
	}

	time.Sleep(2 * time.Second)
	close(results)

	var hosts []DiscoveredHost
	for host := range results {
		hosts = append(hosts, host)
	}
	return hosts
}

func (d *IPv6Discoverer) getLocalHosts() []DiscoveredHost {
	var hosts []DiscoveredHost
	ifaces, err := net.Interfaces()
	if err != nil {
		return hosts
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		//检查网络接口是否有物理地址
		mac := iface.HardwareAddr.String() // 获取接口的MAC地址
		if mac == "" {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil {
				ip := ipnet.IP.String()
				if ipnet.IP.IsGlobalUnicast() || ipnet.IP.IsLinkLocalUnicast() {
					hosts = append(hosts, DiscoveredHost{IP: ip, MAC: mac})
				}
			}
		}
	}
	return hosts
}

func (d *IPv6Discoverer) Discover() []DiscoveredHost {
	log.Printf("Starting IPv6 Multicast Echo Discovery on %s...", runtime.GOOS)

	d.runMulticastPing()
	time.Sleep(2 * time.Second)

	allHosts := make(map[string]DiscoveredHost)

	// 并行获取所有类型的主机
	neighborChan := make(chan []DiscoveredHost, 1)
	localChan := make(chan []DiscoveredHost, 1)

	go func() { neighborChan <- d.getActiveHosts() }()
	go func() { localChan <- d.getLocalHosts() }()

	neighbors := <-neighborChan
	locals := <-localChan

	// 合并结果，网络设备优选全局地址，本机保留所有地址
	for _, host := range neighbors {
		allHosts[host.IP+"|"+host.MAC] = host
	}
	for _, host := range locals {
		allHosts[host.IP+"|"+host.MAC] = host
	}

	var hosts []DiscoveredHost
	for _, host := range allHosts {
		hosts = append(hosts, host)
	}

	// 按IPv6地址的字符串字典序排序
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	return hosts
}

func isAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("net", "session").Run() == nil
	case "darwin", "linux":
		return os.Geteuid() == 0
	default:
		return false
	}
}

func Ipv6_scan() {
	fmt.Println("开始ipv6探测...")

	start := time.Now()

	//检查是否为管理员权限运行
	if !isAdmin() {
		fmt.Println("没有使用管理员权限运行，一些功能可能被限制")
	}

	fmt.Println("探测方法: 多播 + 邻居表查询 + 本地接口扫描")
	fmt.Println()

	hosts := NewIPv6Discoverer(timeoutSeconds * time.Second).Discover()

	fmt.Println("/n探测结果：")
	if len(hosts) > 0 {
		for _, host := range hosts {
			fmt.Printf("IP: %-50s MAC: %s\n", host.IP, host.MAC)
		}
	} else {
		fmt.Println("No hosts discovered")
	}
	fmt.Printf("\n共发现: %d 个地址\n", len(hosts))

	usetime := time.Now().Sub(start)
	fmt.Printf("运行时间:%v 秒\n", usetime)
}
