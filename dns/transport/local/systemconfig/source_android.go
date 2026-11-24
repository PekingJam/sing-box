//go:build android

package systemconfig

import (
	"bufio"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

// Android 没有 /etc/resolv.conf：系统 DNS 由 netd 持有，Wi-Fi 与移动数据各自一份。
// 这里通过 `dumpsys connectivity`（root 或 shell 均可执行，约 30ms）读出当前默认网络的
// DNS 地址，再交给上层照常做 UDP/TCP 查询，因此不依赖 cgo，也不会绕过系统策略。

const (
	androidDumpsysPath    = "/system/bin/dumpsys"
	androidCacheLifetime  = 5 * time.Second
	androidQueryTimeout   = 3 * time.Second
	androidMaxServerCount = 3
)

var (
	androidNetworkIDPattern = regexp.MustCompile(`network\{(\d+)\}`)
	androidDNSPattern       = regexp.MustCompile(`DnsAddresses:\s*\[([^\]]*)\]`)
	androidDomainPattern    = regexp.MustCompile(`Domains:\s*([^\s}\]]+)`)
)

// androidTransports 按「越具体越好」的顺序匹配链路类型。
var androidTransports = []string{
	"WIFI", "CELLULAR", "ETHERNET", "VPN", "BLUETOOTH",
}

type androidNetwork struct {
	id        int
	transport string
	servers   []string
	domains   []string
}

type androidConfig struct {
	config    *Config
	signature string
}

// Source 是 systemconfig.Source 的 Android 实现，接口与 resolv.conf 版保持一致。
type Source struct {
	updateAccess sync.Mutex
	lastChecked  time.Time
	current      atomic.Pointer[androidConfig]
}

func NewSource(_ context.Context) *Source {
	source := &Source{lastChecked: time.Now()}
	config, signature := readAndroidConfig()
	if config == nil {
		config, signature = androidGatewayConfig()
	}
	source.current.Store(&androidConfig{config: config, signature: signature})
	return source
}

func (s *Source) Configuration() *Config {
	s.tryUpdate()
	return s.current.Load().config
}

func (s *Source) tryUpdate() {
	if !s.updateAccess.TryLock() {
		return
	}
	defer s.updateAccess.Unlock()
	now := time.Now()
	if s.lastChecked.After(now.Add(-androidCacheLifetime)) {
		return
	}
	s.lastChecked = now
	config, signature := readAndroidConfig()
	if config == nil {
		// 读不到就保留上一次可用的配置（换网瞬间 dumpsys 偶尔会短暂失败）
		return
	}
	current := s.current.Load()
	if signature == current.signature {
		return
	}
	if current.config != nil && config.Equal(current.config) {
		signature = current.signature
	}
	s.current.Store(&androidConfig{config: config, signature: signature})
}

func (s *Source) Reset() {
	s.updateAccess.Lock()
	s.lastChecked = time.Time{}
	s.updateAccess.Unlock()
}

func (s *Source) Close() error {
	return nil
}

func readAndroidConfig() (*Config, string) {
	ctx, cancel := context.WithTimeout(context.Background(), androidQueryTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, androidDumpsysPath, "connectivity").Output()
	if err != nil {
		return nil, ""
	}
	return parseAndroidConfig(string(output))
}

func parseAndroidConfig(output string) (*Config, string) {
	activeID := -1
	networks := make([]*androidNetwork, 0, 4)
	var current *androidNetwork

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Active default network:") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 4 {
				if id, parseErr := strconv.Atoi(fields[3]); parseErr == nil {
					activeID = id
				}
			}
			continue
		}
		if strings.Contains(line, "NetworkAgentInfo{") {
			current = &androidNetwork{id: -1, transport: androidTransport(line)}
			if match := androidNetworkIDPattern.FindStringSubmatch(line); match != nil {
				current.id, _ = strconv.Atoi(match[1])
			}
			current.servers = append(current.servers, androidServers(line)...)
			current.domains = append(current.domains, androidDomains(line)...)
			networks = append(networks, current)
			continue
		}
		if current == nil {
			continue
		}
		// 多行打印时，后续缩进行仍属于同一个 NetworkAgentInfo
		if trimmed == "" || !strings.HasPrefix(line, " ") {
			current = nil
			continue
		}
		current.servers = append(current.servers, androidServers(line)...)
		current.domains = append(current.domains, androidDomains(line)...)
		if transport := androidTransport(line); transport != "" && current.transport == "" {
			current.transport = transport
		}
	}

	chosen := pickAndroidNetwork(networks, activeID)
	if chosen == nil {
		return nil, ""
	}

	config := &Config{
		Timeout:  5 * time.Second,
		Attempts: 2,
	}
	signature := make([]string, 0, androidMaxServerCount+len(chosen.domains))
	seen := make(map[netip.Addr]bool, len(chosen.servers))
	for _, server := range chosen.servers {
		if len(config.Servers) >= androidMaxServerCount {
			break
		}
		address, err := parseAndroidAddress(server)
		if err != nil || seen[address] {
			continue
		}
		seen[address] = true
		config.Servers = append(config.Servers, M.SocksaddrFrom(address, 53))
		signature = append(signature, address.String())
	}
	if len(config.Servers) == 0 {
		return nil, ""
	}
	for _, domain := range chosen.domains {
		if domain == "" || domain == "null" {
			continue
		}
		name := mDNS.Fqdn(domain)
		if name == "." {
			continue
		}
		config.Search = append(config.Search, name)
		signature = append(signature, name)
	}
	if len(config.Search) == 0 {
		config.Search = defaultSearch()
	}
	return config, strings.Join(signature, ",")
}

// pickAndroidNetwork 优先取默认网络；VPN 场景下默认网络没有可用 DNS，就退回物理网络的。
func pickAndroidNetwork(networks []*androidNetwork, activeID int) *androidNetwork {
	for _, network := range networks {
		if network.id == activeID && network.transport != "vpn" && len(network.servers) > 0 {
			return network
		}
	}
	for _, network := range networks {
		if network.transport != "vpn" && len(network.servers) > 0 {
			return network
		}
	}
	for _, network := range networks {
		if len(network.servers) > 0 {
			return network
		}
	}
	return nil
}

func androidServers(line string) []string {
	match := androidDNSPattern.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	servers := make([]string, 0, 2)
	for _, field := range strings.Split(match[1], ",") {
		field = strings.TrimSpace(field)
		field = strings.TrimSpace(strings.TrimPrefix(field, "/"))
		if field == "" || field == "null" {
			continue
		}
		servers = append(servers, field)
	}
	return servers
}

func androidDomains(line string) []string {
	match := androidDomainPattern.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	domains := make([]string, 0, 2)
	for _, domain := range strings.Split(match[1], ",") {
		domain = strings.TrimSpace(domain)
		if domain == "" || domain == "null" {
			continue
		}
		domains = append(domains, domain)
	}
	return domains
}

func androidTransport(line string) string {
	for _, transport := range androidTransports {
		if strings.Contains(line, "ni{"+transport) ||
			strings.Contains(line, "Transports: "+transport) {
			return strings.ToLower(transport)
		}
	}
	return ""
}

// parseAndroidAddress 处理 `/192.168.0.1`、`fe80::1%wlan0` 这类 dumpsys 写法。
func parseAndroidAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "/"))
	if index := strings.IndexByte(value, '%'); index >= 0 {
		value = value[:index]
	}
	return netip.ParseAddr(value)
}

// androidGatewayConfig 是最后的兜底：dumpsys 读不出来时用默认网关当 DNS（Wi-Fi 下通常成立）。
func androidGatewayConfig() (*Config, string) {
	gateway, err := androidDefaultGateway()
	if err != nil {
		config := &Config{Timeout: 5 * time.Second, Attempts: 2}
		config.Servers = defaultServers
		config.Search = defaultSearch()
		return config, ""
	}
	config := &Config{Timeout: 5 * time.Second, Attempts: 2}
	config.Servers = []M.Socksaddr{M.SocksaddrFrom(gateway, 53)}
	config.Search = defaultSearch()
	return config, gateway.String()
}

func androidDefaultGateway() (netip.Addr, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan() // 跳过表头
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[2], 16, 32)
		if parseErr != nil {
			continue
		}
		var address [4]byte
		// /proc/net/route 里的网关是小端序的十六进制
		binary.LittleEndian.PutUint32(address[:], uint32(value))
		return netip.AddrFrom4(address), nil
	}
	return netip.Addr{}, os.ErrNotExist
}
