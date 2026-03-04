package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGeneralSubscription_SingboxJSON_Basic(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "ss-us", "server": "1.2.3.4", "server_port": 443},
			{"type": "vmess", "tag": "vmess-jp", "server": "5.6.7.8", "server_port": 443},
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
			{"type": "selector", "tag": "proxy", "outbounds": ["ss-us", "vmess-jp"]}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}

	// Only shadowsocks and vmess are supported; direct/block/selector are not.
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	if nodes[0].Tag != "ss-us" {
		t.Fatalf("expected tag ss-us, got %s", nodes[0].Tag)
	}
	if nodes[1].Tag != "vmess-jp" {
		t.Fatalf("expected tag vmess-jp, got %s", nodes[1].Tag)
	}
}

func TestParseGeneralSubscription_SingboxJSON_AllSupportedTypes(t *testing.T) {
	types := []string{
		"socks", "http", "shadowsocks", "vmess", "trojan", "wireguard",
		"hysteria", "vless", "shadowtls", "tuic", "hysteria2", "anytls",
		"tor", "ssh", "naive",
	}

	// Build JSON with all supported types.
	outbounds := "["
	for i, tp := range types {
		if i > 0 {
			outbounds += ","
		}
		outbounds += `{"type":"` + tp + `","tag":"node-` + tp + `"}`
	}
	outbounds += "]"

	data := []byte(`{"outbounds":` + outbounds + `}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != len(types) {
		t.Fatalf("expected %d nodes, got %d", len(types), len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_UnsupportedTypesFiltered(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
			{"type": "selector", "tag": "sel"},
			{"type": "urltest", "tag": "urltest"},
			{"type": "dns", "tag": "dns"}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_EmptyOutbounds(t *testing.T) {
	data := []byte(`{"outbounds": []}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_MalformedJSON(t *testing.T) {
	_, err := ParseGeneralSubscription([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseGeneralSubscription_SingboxJSON_MalformedOutboundSkipped(t *testing.T) {
	// A bare number is not a valid JSON object for an outbound — should be skipped.
	data := []byte(`{"outbounds": [123]}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatalf("malformed individual outbound should be skipped, not fatal: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes after skipping bad entry, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_MixedGoodAndBadOutbounds(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "good-node", "server": "1.2.3.4", "server_port": 443},
			123,
			"bad-string",
			{"type": "vmess", "tag": "also-good", "server": "5.6.7.8", "server_port": 443}
		]
	}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatalf("should skip bad entries, not fail: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 valid nodes, got %d", len(nodes))
	}
	if nodes[0].Tag != "good-node" || nodes[1].Tag != "also-good" {
		t.Fatalf("unexpected tags: %s, %s", nodes[0].Tag, nodes[1].Tag)
	}
}

func TestParseGeneralSubscription_SingboxJSON_RawOptionsPreservesFullJSON(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "server_port": 443, "method": "aes-256-gcm"}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}

	// RawOptions should contain the full original JSON.
	raw := string(nodes[0].RawOptions)
	if len(raw) == 0 {
		t.Fatal("RawOptions should not be empty")
	}
	// Should contain method field.
	if !strings.Contains(raw, "aes-256-gcm") {
		t.Fatalf("RawOptions missing method: %s", raw)
	}
}

func TestParseGeneralSubscription_ClashJSON(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "ss-test",
				"type": "ss",
				"server": "1.1.1.1",
				"port": 8388,
				"cipher": "aes-128-gcm",
				"password": "pass"
			},
			{
				"name": "http-test",
				"type": "http",
				"server": "2.2.2.2",
				"port": 8080,
				"username": "user-http",
				"password": "pass-http"
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)
	if got := first["type"]; got != "shadowsocks" {
		t.Fatalf("expected type shadowsocks, got %v", got)
	}
	if got := first["tag"]; got != "ss-test" {
		t.Fatalf("expected tag ss-test, got %v", got)
	}
	if got := second["type"]; got != "http" {
		t.Fatalf("expected type http, got %v", got)
	}
	if got := second["tag"]; got != "http-test" {
		t.Fatalf("expected tag http-test, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashYAML(t *testing.T) {
	data := []byte(`
proxies:
  - name: vmess-yaml
    type: vmess
    server: 3.3.3.3
    port: 443
    uuid: 26a1d547-b031-4139-9fc5-6671e1d0408a
    cipher: auto
    tls: true
    servername: example.com
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}

	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "vmess" {
		t.Fatalf("expected type vmess, got %v", got)
	}
	if got := obj["tag"]; got != "vmess-yaml" {
		t.Fatalf("expected tag vmess-yaml, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashJSON_NewProtocolsAndDialFields(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "socks-test",
				"type": "socks5",
				"server": "1.1.1.1",
				"port": 1080,
				"username": "socks-user",
				"password": "socks-pass",
				"udp": false,
				"dialer-proxy": "detour-a",
				"bind-interface": "eth0",
				"routing-mark": "0x20",
				"fast-open": true,
				"mptcp": true,
				"udp-fragment": true,
				"ip-version": "ipv6"
			},
			{
				"name": "http-test",
				"type": "http",
				"server": "2.2.2.2",
				"port": 443,
				"username": "http-user",
				"password": "http-pass",
				"headers": {"x-token": "abc"},
				"tls": true,
				"sni": "custom.com",
				"skip-cert-verify": true
			},
			{
				"name": "wg-test",
				"type": "wireguard",
				"server": "162.159.192.1",
				"port": 2480,
				"private-key": "priv-key",
				"public-key": "pub-key",
				"pre-shared-key": "psk",
				"ip": "172.16.0.2",
				"ipv6": "fd01::1",
				"allowed-ips": ["0.0.0.0/0", "::/0"],
				"reserved": [209, 98, 59],
				"mtu": 1408,
				"udp": false,
				"ip-version": "prefer-ipv4"
			},
			{
				"name": "hy-test",
				"type": "hysteria",
				"server": "server.com",
				"port": 443,
				"auth-str": "yourpassword",
				"obfs": "obfs-str",
				"up": "30",
				"down": "200",
				"ports": "1000,2000-3000",
				"protocol": "udp",
				"recv-window-conn": 12582912,
				"recv-window": 52428800,
				"disable_mtu_discovery": true,
				"sni": "server.com",
				"skip-cert-verify": true,
				"alpn": ["h3"]
			},
			{
				"name": "tuic-test",
				"type": "tuic",
				"server": "www.example.com",
				"port": 10443,
				"uuid": "00000000-0000-0000-0000-000000000001",
				"password": "PASSWORD_1",
				"congestion-controller": "bbr",
				"udp-relay-mode": "native",
				"reduce-rtt": true,
				"heartbeat-interval": 10000,
				"disable-sni": true,
				"sni": "example.com",
				"skip-cert-verify": true,
				"alpn": ["h3"]
			},
			{
				"name": "anytls-test",
				"type": "anytls",
				"server": "1.2.3.4",
				"port": 443,
				"password": "anytls-pass",
				"idle-session-check-interval": 30,
				"idle-session-timeout": 40,
				"min-idle-session": 2,
				"sni": "example.com",
				"skip-cert-verify": true,
				"alpn": ["h2", "http/1.1"],
				"client-fingerprint": "chrome"
			},
			{
				"name": "ssh-test",
				"type": "ssh",
				"server": "127.0.0.1",
				"port": 22,
				"username": "root",
				"password": "password",
				"private-key": "key",
				"private-key-passphrase": "key-password",
				"host-key": ["ssh-rsa AAAAB3Nza..."],
				"host-key-algorithms": ["rsa"],
				"client-version": "SSH-2.0-OpenSSH_7.4p1"
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 7 {
		t.Fatalf("expected 7 parsed nodes, got %d", len(nodes))
	}

	byTag := parseNodesByTag(t, nodes)

	socks := byTag["socks-test"]
	if got := socks["type"]; got != "socks" {
		t.Fatalf("socks type: got %v", got)
	}
	if got := socks["version"]; got != "5" {
		t.Fatalf("socks version: got %v", got)
	}
	if got := socks["network"]; got != "tcp" {
		t.Fatalf("socks network: got %v", got)
	}
	if got := socks["detour"]; got != "detour-a" {
		t.Fatalf("socks detour: got %v", got)
	}
	if got := socks["bind_interface"]; got != "eth0" {
		t.Fatalf("socks bind_interface: got %v", got)
	}
	if got := socks["routing_mark"]; got != "0x20" {
		t.Fatalf("socks routing_mark: got %v", got)
	}
	if got := socks["tcp_fast_open"]; got != true {
		t.Fatalf("socks tcp_fast_open: got %v", got)
	}
	if got := socks["tcp_multi_path"]; got != true {
		t.Fatalf("socks tcp_multi_path: got %v", got)
	}
	if got := socks["udp_fragment"]; got != true {
		t.Fatalf("socks udp_fragment: got %v", got)
	}
	if got := socks["domain_strategy"]; got != "ipv6_only" {
		t.Fatalf("socks domain_strategy: got %v", got)
	}

	httpNode := byTag["http-test"]
	if got := httpNode["type"]; got != "http" {
		t.Fatalf("http type: got %v", got)
	}
	httpTLS := mustMapField(t, httpNode, "tls")
	if got := httpTLS["enabled"]; got != true {
		t.Fatalf("http tls.enabled: got %v", got)
	}
	if got := httpTLS["server_name"]; got != "custom.com" {
		t.Fatalf("http tls.server_name: got %v", got)
	}
	if got := httpTLS["insecure"]; got != true {
		t.Fatalf("http tls.insecure: got %v", got)
	}

	wireGuard := byTag["wg-test"]
	if got := wireGuard["type"]; got != "wireguard" {
		t.Fatalf("wireguard type: got %v", got)
	}
	if got := wireGuard["private_key"]; got != "priv-key" {
		t.Fatalf("wireguard private_key: got %v", got)
	}
	if got := wireGuard["peer_public_key"]; got != "pub-key" {
		t.Fatalf("wireguard peer_public_key: got %v", got)
	}
	if got := wireGuard["pre_shared_key"]; got != "psk" {
		t.Fatalf("wireguard pre_shared_key: got %v", got)
	}
	if got := wireGuard["network"]; got != "tcp" {
		t.Fatalf("wireguard network: got %v", got)
	}
	if got := wireGuard["domain_strategy"]; got != "prefer_ipv4" {
		t.Fatalf("wireguard domain_strategy: got %v", got)
	}
	localAddress := mustSliceField(t, wireGuard, "local_address")
	if !containsAnyString(localAddress, "172.16.0.2/32") {
		t.Fatalf("wireguard local_address missing ipv4 entry: %v", localAddress)
	}
	if !containsAnyString(localAddress, "fd01::1/128") {
		t.Fatalf("wireguard local_address missing ipv6 entry: %v", localAddress)
	}
	topReserved := mustSliceField(t, wireGuard, "reserved")
	if len(topReserved) != 3 {
		t.Fatalf("wireguard reserved length: got %d", len(topReserved))
	}

	hysteria := byTag["hy-test"]
	if got := hysteria["type"]; got != "hysteria" {
		t.Fatalf("hysteria type: got %v", got)
	}
	if got := hysteria["up"]; got != "30 Mbps" {
		t.Fatalf("hysteria up: got %v", got)
	}
	if got := hysteria["down"]; got != "200 Mbps" {
		t.Fatalf("hysteria down: got %v", got)
	}
	if got := hysteria["network"]; got != "udp" {
		t.Fatalf("hysteria network: got %v", got)
	}
	serverPorts := mustSliceField(t, hysteria, "server_ports")
	if !containsAnyString(serverPorts, "1000") || !containsAnyString(serverPorts, "2000-3000") {
		t.Fatalf("hysteria server_ports mismatch: %v", serverPorts)
	}

	tuic := byTag["tuic-test"]
	if got := tuic["type"]; got != "tuic" {
		t.Fatalf("tuic type: got %v", got)
	}
	if got := tuic["congestion_control"]; got != "bbr" {
		t.Fatalf("tuic congestion_control: got %v", got)
	}
	if got := tuic["udp_relay_mode"]; got != "native" {
		t.Fatalf("tuic udp_relay_mode: got %v", got)
	}
	if got := tuic["zero_rtt_handshake"]; got != true {
		t.Fatalf("tuic zero_rtt_handshake: got %v", got)
	}
	if got := tuic["heartbeat"]; got != "10000ms" {
		t.Fatalf("tuic heartbeat: got %v", got)
	}
	tuicTLS := mustMapField(t, tuic, "tls")
	if got := tuicTLS["disable_sni"]; got != true {
		t.Fatalf("tuic tls.disable_sni: got %v", got)
	}
	if got := tuicTLS["server_name"]; got != "example.com" {
		t.Fatalf("tuic tls.server_name: got %v", got)
	}

	anytls := byTag["anytls-test"]
	if got := anytls["type"]; got != "anytls" {
		t.Fatalf("anytls type: got %v", got)
	}
	if got := anytls["idle_session_check_interval"]; got != "30s" {
		t.Fatalf("anytls idle_session_check_interval: got %v", got)
	}
	if got := anytls["idle_session_timeout"]; got != "40s" {
		t.Fatalf("anytls idle_session_timeout: got %v", got)
	}
	if got := anytls["min_idle_session"]; got != float64(2) {
		t.Fatalf("anytls min_idle_session: got %v", got)
	}
	anyTLSTLS := mustMapField(t, anytls, "tls")
	utls := mustMapField(t, anyTLSTLS, "utls")
	if got := utls["enabled"]; got != true {
		t.Fatalf("anytls tls.utls.enabled: got %v", got)
	}
	if got := utls["fingerprint"]; got != "chrome" {
		t.Fatalf("anytls tls.utls.fingerprint: got %v", got)
	}

	ssh := byTag["ssh-test"]
	if got := ssh["type"]; got != "ssh" {
		t.Fatalf("ssh type: got %v", got)
	}
	if got := ssh["user"]; got != "root" {
		t.Fatalf("ssh user: got %v", got)
	}
	if got := ssh["private_key"]; got != "key" {
		t.Fatalf("ssh private_key: got %v", got)
	}
	if got := ssh["private_key_passphrase"]; got != "key-password" {
		t.Fatalf("ssh private_key_passphrase: got %v", got)
	}
	hostKeyAlgorithms := mustSliceField(t, ssh, "host_key_algorithms")
	if !containsAnyString(hostKeyAlgorithms, "rsa") {
		t.Fatalf("ssh host_key_algorithms: got %v", hostKeyAlgorithms)
	}
}

func TestParseGeneralSubscription_ClashJSON_TUICWithoutUUIDIsSkipped(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "tuic-token-only",
				"type": "tuic",
				"server": "www.example.com",
				"port": 10443,
				"token": "TOKEN"
			},
			{
				"name": "ss-test",
				"type": "ss",
				"server": "1.1.1.1",
				"port": 8388,
				"cipher": "aes-128-gcm",
				"password": "pass"
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}
	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["tag"]; got != "ss-test" {
		t.Fatalf("expected ss-test to remain, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashJSON_WireGuardMissingAddressIsSkipped(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "wg-missing-address",
				"type": "wireguard",
				"server": "162.159.192.1",
				"port": 2480,
				"private-key": "priv-key",
				"public-key": "pub-key"
			},
			{
				"name": "http-ok",
				"type": "http",
				"server": "2.2.2.2",
				"port": 8080
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}
	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "http" {
		t.Fatalf("expected remaining node type http, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashJSON_WireGuardMissingAllowedIPsIsSkipped(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "wg-missing-allowed-ips",
				"type": "wireguard",
				"server": "162.159.192.1",
				"port": 2480,
				"private-key": "priv-key",
				"public-key": "pub-key",
				"ip": "172.16.0.2"
			},
			{
				"name": "socks-ok",
				"type": "socks5",
				"server": "1.1.1.1",
				"port": 1080
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}
	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "socks" {
		t.Fatalf("expected remaining node type socks, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashJSON_HysteriaNonUDPProtocolIgnored(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "hy-faketcp",
				"type": "hysteria",
				"server": "server.com",
				"port": 443,
				"auth-str": "yourpassword",
				"up": "30 Mbps",
				"down": "200 Mbps",
				"protocol": "faketcp"
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}
	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "hysteria" {
		t.Fatalf("expected hysteria node, got %v", got)
	}
	if _, exists := obj["network"]; exists {
		t.Fatalf("expected protocol=faketcp to be ignored, got network=%v", obj["network"])
	}
}

func TestParseGeneralSubscription_ClashJSON_HTTPAndSOCKSUnsupportedFieldsIgnored(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "socks-extra",
				"type": "socks",
				"server": "1.1.1.1",
				"port": 1080,
				"tls": true,
				"fingerprint": "xxxx",
				"skip-cert-verify": true
			},
			{
				"name": "http-extra",
				"type": "http",
				"server": "2.2.2.2",
				"port": 443,
				"tls": true,
				"sni": "custom.com",
				"fingerprint": "xxxx"
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	byTag := parseNodesByTag(t, nodes)
	socks := byTag["socks-extra"]
	if _, exists := socks["tls"]; exists {
		t.Fatalf("expected socks tls to be ignored, got %v", socks["tls"])
	}
	httpNode := byTag["http-extra"]
	if _, exists := httpNode["fingerprint"]; exists {
		t.Fatalf("expected http fingerprint to be ignored, got %v", httpNode["fingerprint"])
	}
}

func TestParseGeneralSubscription_URILines(t *testing.T) {
	data := []byte(`
trojan://password@example.com:443?allowInsecure=1&type=ws&sni=example.com#Trojan%20Node
vless://26a1d547-b031-4139-9fc5-6671e1d0408a@example.com:443?type=tcp&security=tls&sni=example.com#VLESS%20Node
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)
	if first["type"] != "trojan" || second["type"] != "vless" {
		t.Fatalf("unexpected node types: %v, %v", first["type"], second["type"])
	}
}

func TestParseGeneralSubscription_ProxyURILines(t *testing.T) {
	data := []byte(`
http://user-http:pass-http@1.2.3.4:8080#HTTP%20Node
https://user-https:pass-https@example.com:8443?sni=tls.example.com&allowInsecure=1#HTTPS%20Node
socks5://user-s5:pass-s5@5.6.7.8:1081#SOCKS5%20Node
socks5h://user-s5h:pass-s5h@proxy.example.net:1082#SOCKS5H%20Node
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 4 {
		t.Fatalf("expected 4 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)
	third := parseNodeRaw(t, nodes[2].RawOptions)
	fourth := parseNodeRaw(t, nodes[3].RawOptions)

	if got := first["type"]; got != "http" {
		t.Fatalf("expected first type http, got %v", got)
	}
	if got := first["username"]; got != "user-http" {
		t.Fatalf("expected first username user-http, got %v", got)
	}
	if got := first["password"]; got != "pass-http" {
		t.Fatalf("expected first password pass-http, got %v", got)
	}
	if got := first["tag"]; got != "HTTP Node" {
		t.Fatalf("expected first tag HTTP Node, got %v", got)
	}

	if got := second["type"]; got != "http" {
		t.Fatalf("expected second type http, got %v", got)
	}
	tls, ok := second["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected second tls object, got %T", second["tls"])
	}
	if got := tls["enabled"]; got != true {
		t.Fatalf("expected second tls.enabled true, got %v", got)
	}
	if got := tls["server_name"]; got != "tls.example.com" {
		t.Fatalf("expected second tls.server_name tls.example.com, got %v", got)
	}
	if got := tls["insecure"]; got != true {
		t.Fatalf("expected second tls.insecure true, got %v", got)
	}
	if got := second["tag"]; got != "HTTPS Node" {
		t.Fatalf("expected second tag HTTPS Node, got %v", got)
	}

	if got := third["type"]; got != "socks" {
		t.Fatalf("expected third type socks, got %v", got)
	}
	if got := third["server"]; got != "5.6.7.8" {
		t.Fatalf("expected third server 5.6.7.8, got %v", got)
	}
	if got := third["server_port"]; got != float64(1081) {
		t.Fatalf("expected third server_port 1081, got %v", got)
	}
	if got := third["username"]; got != "user-s5" {
		t.Fatalf("expected third username user-s5, got %v", got)
	}
	if got := third["password"]; got != "pass-s5" {
		t.Fatalf("expected third password pass-s5, got %v", got)
	}

	if got := fourth["type"]; got != "socks" {
		t.Fatalf("expected fourth type socks, got %v", got)
	}
	if got := fourth["server"]; got != "proxy.example.net" {
		t.Fatalf("expected fourth server proxy.example.net, got %v", got)
	}
	if got := fourth["server_port"]; got != float64(1082) {
		t.Fatalf("expected fourth server_port 1082, got %v", got)
	}
	if got := fourth["username"]; got != "user-s5h" {
		t.Fatalf("expected fourth username user-s5h, got %v", got)
	}
	if got := fourth["password"]; got != "pass-s5h" {
		t.Fatalf("expected fourth password pass-s5h, got %v", got)
	}
}

func TestParseGeneralSubscription_ProxyURILinesRejectNonProxyURLs(t *testing.T) {
	tests := []string{
		"https://api.example.com",
		"https://api.example.com/subscription/token",
		"http://api.example.com:8080/path/to/resource",
		"socks5://proxy.example.com:1080/path",
		"socks5://proxy.example.com:1080?token=abc",
		"https://proxy.example.com:8443?token=abc",
	}

	for _, input := range tests {
		nodes, err := ParseGeneralSubscription([]byte(input))
		if err != nil {
			t.Fatalf("input %q should not return error, got %v", input, err)
		}
		if len(nodes) != 0 {
			t.Fatalf("input %q should not be parsed as proxy node, got %d", input, len(nodes))
		}
	}
}
func TestParseGeneralSubscription_PlainHTTPProxyLines(t *testing.T) {
	data := []byte(`
1.2.3.4:8080
5.6.7.8:3128:user-a:pass-a
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)

	if first["type"] != "http" {
		t.Fatalf("expected first type http, got %v", first["type"])
	}
	if first["server"] != "1.2.3.4" {
		t.Fatalf("expected first server 1.2.3.4, got %v", first["server"])
	}
	if first["server_port"] != float64(8080) {
		t.Fatalf("expected first server_port 8080, got %v", first["server_port"])
	}
	if _, ok := first["username"]; ok {
		t.Fatalf("expected first proxy without username, got %v", first["username"])
	}
	if _, ok := first["password"]; ok {
		t.Fatalf("expected first proxy without password, got %v", first["password"])
	}

	if second["type"] != "http" {
		t.Fatalf("expected second type http, got %v", second["type"])
	}
	if second["server"] != "5.6.7.8" {
		t.Fatalf("expected second server 5.6.7.8, got %v", second["server"])
	}
	if second["server_port"] != float64(3128) {
		t.Fatalf("expected second server_port 3128, got %v", second["server_port"])
	}
	if second["username"] != "user-a" {
		t.Fatalf("expected second username user-a, got %v", second["username"])
	}
	if second["password"] != "pass-a" {
		t.Fatalf("expected second password pass-a, got %v", second["password"])
	}
}

func TestParseGeneralSubscription_PlainHTTPProxyLinesIPv6(t *testing.T) {
	data := []byte(`
[2001:db8::1]:8080
2001:db8::2:3128:user-v6:pass-v6
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)

	if first["type"] != "http" {
		t.Fatalf("expected first type http, got %v", first["type"])
	}
	if first["server"] != "2001:db8::1" {
		t.Fatalf("expected first server 2001:db8::1, got %v", first["server"])
	}
	if first["server_port"] != float64(8080) {
		t.Fatalf("expected first server_port 8080, got %v", first["server_port"])
	}

	if second["type"] != "http" {
		t.Fatalf("expected second type http, got %v", second["type"])
	}
	if second["server"] != "2001:db8::2" {
		t.Fatalf("expected second server 2001:db8::2, got %v", second["server"])
	}
	if second["server_port"] != float64(3128) {
		t.Fatalf("expected second server_port 3128, got %v", second["server_port"])
	}
	if second["username"] != "user-v6" {
		t.Fatalf("expected second username user-v6, got %v", second["username"])
	}
	if second["password"] != "pass-v6" {
		t.Fatalf("expected second password pass-v6, got %v", second["password"])
	}
}

func TestParseGeneralSubscription_Base64WrappedURIs(t *testing.T) {
	plain := "ss://YWVzLTEyOC1nY206cGFzcw==@1.1.1.1:8388#SS-Node"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))

	nodes, err := ParseGeneralSubscription([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}

	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "shadowsocks" {
		t.Fatalf("expected type shadowsocks, got %v", got)
	}
	if got := obj["tag"]; got != "SS-Node" {
		t.Fatalf("expected tag SS-Node, got %v", got)
	}
}

func TestParseGeneralSubscription_UnknownFormatReturnsError(t *testing.T) {
	_, err := ParseGeneralSubscription([]byte("this is not a subscription format"))
	if err == nil {
		t.Fatal("expected error for unknown subscription format")
	}
}

func parseNodeRaw(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal node raw failed: %v", err)
	}
	return obj
}

func parseNodesByTag(t *testing.T, nodes []ParsedNode) map[string]map[string]any {
	t.Helper()
	byTag := make(map[string]map[string]any, len(nodes))
	for _, node := range nodes {
		obj := parseNodeRaw(t, node.RawOptions)
		tag, _ := obj["tag"].(string)
		byTag[tag] = obj
	}
	return byTag
}

func mustMapField(t *testing.T, obj map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := obj[key]
	if !ok {
		t.Fatalf("missing map field %q", key)
	}
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("field %q expected map[string]any, got %T", key, value)
	}
	return out
}

func mustSliceField(t *testing.T, obj map[string]any, key string) []any {
	t.Helper()
	value, ok := obj[key]
	if !ok {
		t.Fatalf("missing slice field %q", key)
	}
	out, ok := value.([]any)
	if !ok {
		t.Fatalf("field %q expected []any, got %T", key, value)
	}
	return out
}

func containsAnyString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
