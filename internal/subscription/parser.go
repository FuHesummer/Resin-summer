package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// supportedOutboundTypes is the set of outbound types that Resin manages.
var supportedOutboundTypes = map[string]bool{
	"socks":       true,
	"http":        true,
	"shadowsocks": true,
	"vmess":       true,
	"trojan":      true,
	"wireguard":   true,
	"hysteria":    true,
	"vless":       true,
	"shadowtls":   true,
	"tuic":        true,
	"hysteria2":   true,
	"anytls":      true,
	"tor":         true,
	"ssh":         true,
	"naive":       true,
}

// ParsedNode represents a single parsed outbound from a subscription response.
type ParsedNode struct {
	Tag              string          // original tag from the outbound config
	RawOptions       json.RawMessage // full outbound JSON (including tag)
	DependencyBundle json.RawMessage // optional dependency outbounds for detour chains
}

type outboundDependencyBundle struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

// subscriptionResponse is the top-level structure of a sing-box subscription.
type subscriptionResponse struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

// outboundHeader extracts just the type and tag from an outbound entry.
type outboundHeader struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type parseAttempt struct {
	nodes      []ParsedNode
	recognized bool
}

// GeneralSubscriptionParser parses common subscription formats and extracts
// sing-box outbound nodes.
type GeneralSubscriptionParser struct{}

// NewGeneralSubscriptionParser creates a general multi-format parser.
func NewGeneralSubscriptionParser() *GeneralSubscriptionParser {
	return &GeneralSubscriptionParser{}
}

// ParseGeneralSubscription parses sing-box JSON / Clash JSON|YAML / URI-line
// subscriptions (vmess/vless/trojan/ss/hysteria2/http/https/socks5/socks5h),
// plus plain HTTP proxy lines (IP:PORT or IP:PORT:USER:PASS), with optional
// base64-wrapped content support.
func ParseGeneralSubscription(data []byte) ([]ParsedNode, error) {
	return NewGeneralSubscriptionParser().Parse(data)
}

// Parse parses subscription content and returns supported outbound nodes.
func (p *GeneralSubscriptionParser) Parse(data []byte) ([]ParsedNode, error) {
	normalized := normalizeInput(data)
	if len(normalized) == 0 {
		return nil, fmt.Errorf("subscription: empty response")
	}

	attempt, err := parseSubscriptionContent(normalized)
	if err != nil {
		return nil, err
	}
	if attempt.recognized {
		return attempt.nodes, nil
	}

	if decodedText, ok := tryDecodeBase64ToText(normalized); ok {
		decodedAttempt, decodedErr := parseSubscriptionContent([]byte(decodedText))
		if decodedErr != nil {
			return nil, decodedErr
		}
		if decodedAttempt.recognized {
			return decodedAttempt.nodes, nil
		}
	}

	return nil, fmt.Errorf("subscription: unsupported format or no supported nodes found")
}

func parseSubscriptionContent(data []byte) (parseAttempt, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return parseAttempt{}, nil
	}

	if looksLikeJSON(trimmed) {
		nodes, recognized, err := parseJSONSubscription(trimmed)
		if err != nil {
			return parseAttempt{}, err
		}
		if recognized {
			return parseAttempt{nodes: nodes, recognized: true}, nil
		}
	}

	text := normalizeTextContent(string(trimmed))
	if nodes, recognized, err := parseClashYAMLSubscription(text); err != nil {
		return parseAttempt{}, err
	} else if recognized {
		return parseAttempt{nodes: nodes, recognized: true}, nil
	}

	if nodes, recognized := parseURILineSubscription(text); recognized {
		return parseAttempt{nodes: nodes, recognized: true}, nil
	}

	return parseAttempt{}, nil
}

func parseJSONSubscription(data []byte) ([]ParsedNode, bool, error) {
	var obj map[string]json.RawMessage
	objErr := json.Unmarshal(data, &obj)
	if objErr == nil {
		if outboundsRaw, ok := obj["outbounds"]; ok {
			nodes, err := parseSingboxOutbounds(outboundsRaw)
			return nodes, true, err
		}
		if proxiesRaw, ok := obj["proxies"]; ok {
			nodes, err := parseClashProxiesJSON(proxiesRaw)
			return nodes, true, err
		}
		return nil, false, nil
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		nodes := parseRawOutbounds(arr)
		if len(nodes) == 0 {
			return nil, false, nil
		}
		return nodes, true, nil
	}

	return nil, true, fmt.Errorf("subscription: unmarshal json: %w", objErr)
}

func parseSingboxOutbounds(raw json.RawMessage) ([]ParsedNode, error) {
	var resp subscriptionResponse
	if err := json.Unmarshal(raw, &resp.Outbounds); err != nil {
		return nil, fmt.Errorf("subscription: unmarshal outbounds: %w", err)
	}
	return parseRawOutbounds(resp.Outbounds), nil
}

func parseRawOutbounds(outbounds []json.RawMessage) []ParsedNode {
	nodes := make([]ParsedNode, 0, len(outbounds))
	for _, raw := range outbounds {
		var header outboundHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			// Skip malformed individual outbound — do not fail the entire parse.
			continue
		}
		if !supportedOutboundTypes[header.Type] {
			continue
		}
		nodes = append(nodes, ParsedNode{
			Tag:        header.Tag,
			RawOptions: json.RawMessage(append([]byte(nil), raw...)),
		})
	}
	return nodes
}

func parseClashProxiesJSON(raw json.RawMessage) ([]ParsedNode, error) {
	var proxies []map[string]any
	if err := json.Unmarshal(raw, &proxies); err != nil {
		return nil, fmt.Errorf("subscription: unmarshal clash proxies: %w", err)
	}
	return parseClashProxies(proxies), nil
}

// clashConfig is the top-level Clash YAML structure with both proxies and proxy-groups.
type clashConfig struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []clashGroup     `yaml:"proxy-groups"`
}

// clashGroup represents a Clash proxy-group entry.
type clashGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

func parseClashYAMLSubscription(text string) ([]ParsedNode, bool, error) {
	if !looksLikeClashYAML(text) {
		return nil, false, nil
	}

	var cfg clashConfig
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		return nil, true, fmt.Errorf("subscription: unmarshal clash yaml: %w", err)
	}
	return parseClashProxiesWithDeps(cfg.Proxies, cfg.ProxyGroups), true, nil
}

func parseClashProxies(proxies []map[string]any) []ParsedNode {
	return parseClashProxiesWithDeps(proxies, nil)
}

// parseClashProxiesWithDeps parses Clash proxies and resolves dialer-proxy
// references through proxy-groups to build dependency bundles.
// This enables relay/chain proxy support where a landing node (e.g. 月卡-3ztrt5am)
// uses a transit node (e.g. RainYun-lx) via a proxy-group (e.g. 🇺🇸 美国中转).
func parseClashProxiesWithDeps(proxies []map[string]any, groups []clashGroup) []ParsedNode {
	// Build a name→proxy map for resolving dialer-proxy references.
	proxyByName := make(map[string]map[string]any, len(proxies))
	for _, proxy := range proxies {
		name := strings.TrimSpace(firstNonEmpty(getString(proxy, "name"), getString(proxy, "tag")))
		if name != "" {
			proxyByName[name] = proxy
		}
	}

	// Build a group name→first proxy name map for resolving group references.
	// In Clash, proxy-groups like "🇺🇸 美国中转" with type "select" contain a list
	// of proxies. We resolve to the first proxy in the group (the default selection).
	groupFirstProxy := make(map[string]string, len(groups))
	for _, g := range groups {
		if len(g.Proxies) > 0 {
			groupFirstProxy[g.Name] = g.Proxies[0]
		}
	}

	nodes := make([]ParsedNode, 0, len(proxies))
	for _, proxy := range proxies {
		node, ok := convertClashProxyToNode(proxy)
		if !ok {
			continue
		}
		// Check if this node has a dialer-proxy (detour) reference.
		detour := strings.TrimSpace(getString(proxy, "dialer-proxy", "dialer_proxy"))
		if detour != "" {
			depBundle := resolveDialerProxyDeps(detour, proxyByName, groupFirstProxy)
			if depBundle != nil {
				node.DependencyBundle = depBundle
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// resolveDialerProxyDeps resolves a dialer-proxy name to a concrete proxy (possibly
// through a proxy-group indirection) and builds a DependencyBundle containing the
// dependency outbound(s) needed for the detour chain.
func resolveDialerProxyDeps(detourName string, proxyByName map[string]map[string]any, groupFirstProxy map[string]string) json.RawMessage {
	// Resolve through proxy-groups: if the detour name is a group, follow it
	// to the actual proxy. Guard against cycles with a visited set.
	resolvedName := detourName
	visited := map[string]bool{detourName: true}
	for {
		// Check if resolved name is a direct proxy.
		if _, isProxy := proxyByName[resolvedName]; isProxy {
			break
		}
		// Check if resolved name is a proxy-group.
		firstProxy, isGroup := groupFirstProxy[resolvedName]
		if !isGroup || firstProxy == "" {
			return nil // cannot resolve
		}
		if visited[firstProxy] {
			return nil // cycle detected
		}
		visited[firstProxy] = true
		resolvedName = firstProxy
	}

	// Convert the resolved dependency proxy to a sing-box outbound.
	depProxy := proxyByName[resolvedName]
	depNode, ok := convertClashProxyToNode(depProxy)
	if !ok {
		return nil
	}

	// The dependency outbound's tag must match what the main outbound's "detour"
	// field references. If the detour pointed through a group, the main outbound's
	// detour field has the group name — we need to re-tag the dependency to match.
	// Actually, looking at the sing-box detour field: it references by tag name.
	// The main outbound has detour=detourName. We need the dep outbound's tag to
	// equal detourName so sing-box can find it.
	var depOutbound map[string]any
	if err := json.Unmarshal(depNode.RawOptions, &depOutbound); err != nil {
		return nil
	}
	depOutbound["tag"] = detourName

	depRaw, err := json.Marshal(depOutbound)
	if err != nil {
		return nil
	}

	bundle := outboundDependencyBundle{
		Outbounds: []json.RawMessage{json.RawMessage(depRaw)},
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		return nil
	}
	return bundleRaw
}

func convertClashProxyToNode(proxy map[string]any) (ParsedNode, bool) {
	nodeType := strings.ToLower(strings.TrimSpace(getString(proxy, "type")))
	tag := strings.TrimSpace(firstNonEmpty(getString(proxy, "name"), getString(proxy, "tag")))
	server := strings.TrimSpace(getString(proxy, "server"))
	port, ok := getUint(proxy, "port")
	if !ok || server == "" {
		return ParsedNode{}, false
	}

	switch nodeType {
	case "ss", "shadowsocks":
		method := strings.TrimSpace(firstNonEmpty(getString(proxy, "cipher"), getString(proxy, "method")))
		password := strings.TrimSpace(getString(proxy, "password"))
		if method == "" || password == "" {
			return ParsedNode{}, false
		}
		outbound := map[string]any{
			"type":        "shadowsocks",
			"tag":         defaultTag(tag, "shadowsocks", server, port),
			"server":      server,
			"server_port": port,
			"method":      method,
			"password":    password,
		}
		return buildParsedNode(outbound)
	case "vmess":
		uuid := strings.TrimSpace(getString(proxy, "uuid"))
		if uuid == "" {
			return ParsedNode{}, false
		}
		security := strings.TrimSpace(firstNonEmpty(getString(proxy, "cipher"), getString(proxy, "security")))
		if security == "" {
			security = "auto"
		}
		outbound := map[string]any{
			"type":        "vmess",
			"tag":         defaultTag(tag, "vmess", server, port),
			"server":      server,
			"server_port": port,
			"uuid":        uuid,
			"security":    security,
		}
		if alterID, ok := getUint(proxy, "alterId", "alter_id", "aid"); ok {
			outbound["alter_id"] = alterID
		} else {
			outbound["alter_id"] = uint64(0)
		}
		setTLSFromClash(outbound, proxy, "tls")
		setWSTransportFromClash(outbound, proxy)
		return buildParsedNode(outbound)
	case "vless":
		uuid := strings.TrimSpace(getString(proxy, "uuid"))
		if uuid == "" {
			return ParsedNode{}, false
		}
		outbound := map[string]any{
			"type":        "vless",
			"tag":         defaultTag(tag, "vless", server, port),
			"server":      server,
			"server_port": port,
			"uuid":        uuid,
		}
		if flow := strings.TrimSpace(getString(proxy, "flow")); flow != "" {
			outbound["flow"] = flow
		}
		setTLSFromClash(outbound, proxy, "tls")
		setWSTransportFromClash(outbound, proxy)
		return buildParsedNode(outbound)
	case "trojan":
		password := strings.TrimSpace(getString(proxy, "password"))
		if password == "" {
			return ParsedNode{}, false
		}
		tlsEnabled := true
		if v, ok := getBool(proxy, "tls"); ok {
			tlsEnabled = v
		}
		serverName := firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "servername"),
			getString(proxy, "peer"),
		)
		tls := map[string]any{
			"enabled":     tlsEnabled,
			"server_name": firstNonEmpty(strings.TrimSpace(serverName), server),
		}
		if insecure, ok := getBool(proxy, "skip-cert-verify", "allowInsecure", "insecure"); ok && insecure {
			tls["insecure"] = true
		}
		outbound := map[string]any{
			"type":        "trojan",
			"tag":         defaultTag(tag, "trojan", server, port),
			"server":      server,
			"server_port": port,
			"password":    password,
			"tls":         tls,
		}
		setWSTransportFromClash(outbound, proxy)
		return buildParsedNode(outbound)
	case "hysteria2", "hy2":
		password := strings.TrimSpace(firstNonEmpty(getString(proxy, "password"), getString(proxy, "auth")))
		if password == "" {
			return ParsedNode{}, false
		}
		serverName := firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "peer"),
			getString(proxy, "servername"),
		)
		tls := map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(strings.TrimSpace(serverName), server),
		}
		if insecure, ok := getBool(proxy, "skip-cert-verify", "insecure", "allowInsecure"); ok && insecure {
			tls["insecure"] = true
		}
		if alpn := getStringSlice(proxy, "alpn"); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		outbound := map[string]any{
			"type":        "hysteria2",
			"tag":         defaultTag(tag, "hysteria2", server, port),
			"server":      server,
			"server_port": port,
			"password":    password,
			"tls":         tls,
		}
		return buildParsedNode(outbound)
	case "socks", "socks4", "socks4a", "socks5":
		outbound := map[string]any{
			"type":        "socks",
			"tag":         defaultTag(tag, "socks", server, port),
			"server":      server,
			"server_port": port,
		}
		if version := clashSOCKSVersion(nodeType, proxy); version != "" {
			outbound["version"] = version
		}
		if username := strings.TrimSpace(getString(proxy, "username")); username != "" {
			outbound["username"] = username
		}
		if password := strings.TrimSpace(getString(proxy, "password")); password != "" {
			outbound["password"] = password
		}
		if udp, ok := getBool(proxy, "udp"); ok && !udp {
			outbound["network"] = "tcp"
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "http":
		outbound := map[string]any{
			"type":        "http",
			"tag":         defaultTag(tag, "http", server, port),
			"server":      server,
			"server_port": port,
		}
		if username := strings.TrimSpace(getString(proxy, "username")); username != "" {
			outbound["username"] = username
		}
		if password := strings.TrimSpace(getString(proxy, "password")); password != "" {
			outbound["password"] = password
		}
		if headers, ok := getMap(proxy, "headers"); ok && len(headers) > 0 {
			outbound["headers"] = headers
		}
		sni := strings.TrimSpace(firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "servername"),
			getString(proxy, "server-name"),
		))
		skipVerify, hasSkipVerify := getBool(proxy, "skip-cert-verify", "allowInsecure", "insecure")
		tlsEnabled := false
		if tls, ok := getBool(proxy, "tls"); ok && tls {
			tlsEnabled = true
		}
		if sni != "" || hasSkipVerify {
			tlsEnabled = true
		}
		if tlsEnabled {
			tls := newClashEnabledTLS(sni, hasSkipVerify && skipVerify, nil)
			outbound["tls"] = tls
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "wireguard", "wg":
		privateKey := strings.TrimSpace(getString(proxy, "private-key", "private_key"))
		publicKey := strings.TrimSpace(getString(proxy, "public-key", "public_key"))
		localAddress := parseWireGuardLocalAddress(proxy)
		allowedIPs := parseWireGuardAllowedIPs(proxy)
		if privateKey == "" || publicKey == "" || len(localAddress) == 0 || len(allowedIPs) == 0 {
			return ParsedNode{}, false
		}
		outbound := map[string]any{
			"type":            "wireguard",
			"tag":             defaultTag(tag, "wireguard", server, port),
			"server":          server,
			"server_port":     port,
			"private_key":     privateKey,
			"peer_public_key": publicKey,
			"local_address":   localAddress,
		}
		peer := map[string]any{
			"server":      server,
			"server_port": port,
			"public_key":  publicKey,
			"allowed_ips": allowedIPs,
		}
		if preSharedKey := strings.TrimSpace(getString(proxy, "pre-shared-key", "pre_shared_key")); preSharedKey != "" {
			outbound["pre_shared_key"] = preSharedKey
			peer["pre_shared_key"] = preSharedKey
		}
		if reserved, ok := getUint8Array(proxy, "reserved"); ok && len(reserved) == 3 {
			outbound["reserved"] = reserved
			peer["reserved"] = reserved
		}
		outbound["peers"] = []map[string]any{peer}
		if mtu, ok := getUint(proxy, "mtu"); ok {
			outbound["mtu"] = mtu
		}
		if udp, ok := getBool(proxy, "udp"); ok && !udp {
			outbound["network"] = "tcp"
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "hysteria":
		authString := strings.TrimSpace(firstNonEmpty(
			getString(proxy, "auth-str", "auth_str"),
			getString(proxy, "auth"),
		))
		if authString == "" {
			return ParsedNode{}, false
		}
		up := normalizeHysteriaRate(getString(proxy, "up"))
		down := normalizeHysteriaRate(getString(proxy, "down"))
		if up == "" || down == "" {
			return ParsedNode{}, false
		}
		sni := strings.TrimSpace(firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "servername"),
			getString(proxy, "server-name"),
		))
		insecure, _ := getBool(proxy, "skip-cert-verify", "allowInsecure", "insecure")
		tls := newClashEnabledTLS(sni, insecure, getStringSlice(proxy, "alpn"))
		outbound := map[string]any{
			"type":        "hysteria",
			"tag":         defaultTag(tag, "hysteria", server, port),
			"server":      server,
			"server_port": port,
			"auth_str":    authString,
			"up":          up,
			"down":        down,
			"tls":         tls,
		}
		if obfs := strings.TrimSpace(getString(proxy, "obfs")); obfs != "" {
			outbound["obfs"] = obfs
		}
		if ports := splitCommaList(getString(proxy, "ports")); len(ports) > 0 {
			outbound["server_ports"] = ports
		}
		if recvWindowConn, ok := getUint(proxy, "recv-window-conn", "recv_window_conn"); ok {
			outbound["recv_window_conn"] = recvWindowConn
		}
		if recvWindow, ok := getUint(proxy, "recv-window", "recv_window"); ok {
			outbound["recv_window"] = recvWindow
		}
		if disableMTUDiscovery, ok := getBool(proxy, "disable_mtu_discovery"); ok {
			outbound["disable_mtu_discovery"] = disableMTUDiscovery
		}
		if strings.EqualFold(strings.TrimSpace(getString(proxy, "protocol")), "udp") {
			outbound["network"] = "udp"
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "tuic":
		uuid := strings.TrimSpace(getString(proxy, "uuid"))
		if uuid == "" {
			return ParsedNode{}, false
		}
		sni := strings.TrimSpace(firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "servername"),
			getString(proxy, "server-name"),
		))
		insecure, _ := getBool(proxy, "skip-cert-verify", "allowInsecure", "insecure")
		tls := newClashEnabledTLS(sni, insecure, getStringSlice(proxy, "alpn"))
		if disableSNI, ok := getBool(proxy, "disable-sni", "disable_sni"); ok && disableSNI {
			tls["disable_sni"] = true
		}
		outbound := map[string]any{
			"type":        "tuic",
			"tag":         defaultTag(tag, "tuic", server, port),
			"server":      server,
			"server_port": port,
			"uuid":        uuid,
			"tls":         tls,
		}
		if password := strings.TrimSpace(getString(proxy, "password")); password != "" {
			outbound["password"] = password
		}
		if congestionControl := strings.TrimSpace(getString(proxy, "congestion-controller", "congestion_control")); congestionControl != "" {
			outbound["congestion_control"] = congestionControl
		}
		if udpRelayMode := strings.TrimSpace(getString(proxy, "udp-relay-mode", "udp_relay_mode")); udpRelayMode != "" {
			outbound["udp_relay_mode"] = udpRelayMode
		}
		if zeroRTT, ok := getBool(proxy, "reduce-rtt", "zero-rtt-handshake", "zero_rtt_handshake"); ok {
			outbound["zero_rtt_handshake"] = zeroRTT
		}
		if heartbeat, ok := getDurationString(proxy, "ms", "heartbeat-interval", "heartbeat_interval", "heartbeat"); ok {
			outbound["heartbeat"] = heartbeat
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "anytls":
		password := strings.TrimSpace(getString(proxy, "password"))
		if password == "" {
			return ParsedNode{}, false
		}
		sni := strings.TrimSpace(firstNonEmpty(
			getString(proxy, "sni"),
			getString(proxy, "servername"),
			getString(proxy, "server-name"),
		))
		insecure, _ := getBool(proxy, "skip-cert-verify", "allowInsecure", "insecure")
		tls := newClashEnabledTLS(sni, insecure, getStringSlice(proxy, "alpn"))
		if fingerprint := strings.TrimSpace(getString(proxy, "client-fingerprint", "client_fingerprint")); fingerprint != "" {
			tls["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": fingerprint,
			}
		}
		outbound := map[string]any{
			"type":        "anytls",
			"tag":         defaultTag(tag, "anytls", server, port),
			"server":      server,
			"server_port": port,
			"password":    password,
			"tls":         tls,
		}
		if interval, ok := getDurationString(proxy, "s", "idle-session-check-interval", "idle_session_check_interval"); ok {
			outbound["idle_session_check_interval"] = interval
		}
		if timeout, ok := getDurationString(proxy, "s", "idle-session-timeout", "idle_session_timeout"); ok {
			outbound["idle_session_timeout"] = timeout
		}
		if minIdle, ok := getUint(proxy, "min-idle-session", "min_idle_session"); ok {
			outbound["min_idle_session"] = minIdle
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	case "ssh":
		outbound := map[string]any{
			"type":        "ssh",
			"tag":         defaultTag(tag, "ssh", server, port),
			"server":      server,
			"server_port": port,
		}
		if user := strings.TrimSpace(firstNonEmpty(getString(proxy, "username"), getString(proxy, "user"))); user != "" {
			outbound["user"] = user
		}
		if password := strings.TrimSpace(getString(proxy, "password")); password != "" {
			outbound["password"] = password
		}
		if privateKey := strings.TrimSpace(getString(proxy, "private-key", "private_key")); privateKey != "" {
			outbound["private_key"] = privateKey
		}
		if passphrase := strings.TrimSpace(getString(proxy, "private-key-passphrase", "private_key_passphrase")); passphrase != "" {
			outbound["private_key_passphrase"] = passphrase
		}
		if hostKey := getStringList(proxy, "host-key", "host_key"); len(hostKey) > 0 {
			outbound["host_key"] = hostKey
		}
		if hostKeyAlgorithms := getStringList(proxy, "host-key-algorithms", "host_key_algorithms"); len(hostKeyAlgorithms) > 0 {
			outbound["host_key_algorithms"] = hostKeyAlgorithms
		}
		if clientVersion := strings.TrimSpace(getString(proxy, "client-version", "client_version")); clientVersion != "" {
			outbound["client_version"] = clientVersion
		}
		applyClashDialFields(outbound, proxy)
		return buildParsedNode(outbound)
	default:
		return ParsedNode{}, false
	}
}

func clashSOCKSVersion(nodeType string, proxy map[string]any) string {
	switch nodeType {
	case "socks4":
		return "4"
	case "socks4a":
		return "4a"
	case "socks5":
		return "5"
	}
	version := strings.TrimSpace(strings.ToLower(getString(proxy, "version")))
	switch version {
	case "4", "4a", "5":
		return version
	default:
		return ""
	}
}

func parseWireGuardLocalAddress(proxy map[string]any) []string {
	var addresses []string
	for _, key := range []string{"ip", "ipv6"} {
		for _, raw := range getStringList(proxy, key) {
			if normalized, ok := normalizeWireGuardPrefix(raw); ok {
				addresses = append(addresses, normalized)
			}
		}
	}
	return addresses
}

func parseWireGuardAllowedIPs(proxy map[string]any) []string {
	var allowedIPs []string
	for _, raw := range getStringList(proxy, "allowed-ips", "allowed_ips") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			allowedIPs = append(allowedIPs, raw)
		}
	}
	return allowedIPs
}

func normalizeWireGuardPrefix(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return value, true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return ip.String() + "/32", true
	}
	return ip.String() + "/128", true
}

func newClashEnabledTLS(serverName string, insecure bool, alpn []string) map[string]any {
	tls := map[string]any{
		"enabled": true,
	}
	if serverName = strings.TrimSpace(serverName); serverName != "" {
		tls["server_name"] = serverName
	}
	if insecure {
		tls["insecure"] = true
	}
	if len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	return tls
}

func splitCommaList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func normalizeHysteriaRate(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if hasLetter(value) {
		return value
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return value + " Mbps"
	}
	return value
}

func applyClashDialFields(outbound map[string]any, proxy map[string]any) {
	if detour := strings.TrimSpace(getString(proxy, "dialer-proxy", "dialer_proxy")); detour != "" {
		outbound["detour"] = detour
	}
	if bindInterface := strings.TrimSpace(firstNonEmpty(
		getString(proxy, "bind-interface"),
		getString(proxy, "bind_interface"),
		getString(proxy, "interface-name"),
		getString(proxy, "interface_name"),
	)); bindInterface != "" {
		outbound["bind_interface"] = bindInterface
	}
	if routingMark, ok := getUint(proxy, "routing-mark", "routing_mark"); ok {
		outbound["routing_mark"] = routingMark
	} else if markText := strings.TrimSpace(getString(proxy, "routing-mark", "routing_mark")); markText != "" {
		outbound["routing_mark"] = markText
	}
	if tcpFastOpen, ok := getBool(proxy, "fast-open", "fast_open", "tfo"); ok {
		outbound["tcp_fast_open"] = tcpFastOpen
	}
	if tcpMultiPath, ok := getBool(proxy, "mptcp", "tcp-multi-path", "tcp_multi_path"); ok {
		outbound["tcp_multi_path"] = tcpMultiPath
	}
	if udpFragment, ok := getBool(proxy, "udp-fragment", "udp_fragment"); ok {
		outbound["udp_fragment"] = udpFragment
	}
	if domainStrategy := mapClashIPVersionToDomainStrategy(getString(proxy, "ip-version", "ip_version")); domainStrategy != "" {
		outbound["domain_strategy"] = domainStrategy
	}
}

func mapClashIPVersionToDomainStrategy(raw string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "_", "-")) {
	case "ipv4":
		return "ipv4_only"
	case "ipv6":
		return "ipv6_only"
	case "prefer-ipv4":
		return "prefer_ipv4"
	case "prefer-ipv6":
		return "prefer_ipv6"
	default:
		return ""
	}
}

func getDurationString(m map[string]any, defaultUnit string, keys ...string) (string, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		if duration, ok := normalizeDurationValue(v, defaultUnit); ok {
			return duration, true
		}
	}
	return "", false
}

func normalizeDurationValue(raw any, defaultUnit string) (string, bool) {
	value := strings.TrimSpace(fmt.Sprint(raw))
	if value == "" {
		return "", false
	}
	if hasLetter(value) {
		return value, true
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		if defaultUnit == "" {
			return value, true
		}
		return value + defaultUnit, true
	}
	return "", false
}

func hasLetter(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == 'µ' {
			return true
		}
	}
	return false
}

func parseURILineSubscription(text string) ([]ParsedNode, bool) {
	var nodes []ParsedNode
	recognized := false
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)
		var (
			node ParsedNode
			ok   bool
		)
		switch {
		case strings.HasPrefix(lower, "vmess://"):
			recognized = true
			node, ok = parseVmessURI(line)
		case strings.HasPrefix(lower, "vless://"):
			recognized = true
			node, ok = parseVlessURI(line)
		case strings.HasPrefix(lower, "trojan://"):
			recognized = true
			node, ok = parseTrojanURI(line)
		case strings.HasPrefix(lower, "ss://"):
			recognized = true
			node, ok = parseSSURI(line)
		case strings.HasPrefix(lower, "hysteria2://"):
			recognized = true
			node, ok = parseHysteria2URI(line)
		case strings.HasPrefix(lower, "http://"),
			strings.HasPrefix(lower, "https://"),
			strings.HasPrefix(lower, "socks5://"),
			strings.HasPrefix(lower, "socks5h://"):
			recognized = true
			node, ok = parseProxyURI(line)
		default:
			node, ok = parsePlainHTTPProxyLine(line)
			if ok {
				recognized = true
			}
		}
		if ok {
			nodes = append(nodes, node)
		}
	}
	return nodes, recognized
}

func parsePlainHTTPProxyLine(line string) (ParsedNode, bool) {
	if strings.Contains(line, "://") {
		return ParsedNode{}, false
	}

	if node, ok := parseHTTPProxyIPPortUserPass(line); ok {
		return node, true
	}
	return parseHTTPProxyIPPort(line)
}

func parseProxyURI(uri string) (ParsedNode, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return ParsedNode{}, false
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	server := strings.TrimSpace(u.Hostname())
	if server == "" {
		return ParsedNode{}, false
	}
	if !isProxyURIPathAllowed(u.Path) {
		return ParsedNode{}, false
	}
	port, ok := parseRequiredURIPort(u)
	if !ok {
		return ParsedNode{}, false
	}

	nodeType := ""
	switch scheme {
	case "http":
		nodeType = "http"
	case "https":
		nodeType = "http"
	case "socks5", "socks5h":
		nodeType = "socks"
	default:
		return ParsedNode{}, false
	}
	if scheme != "https" && strings.TrimSpace(u.RawQuery) != "" {
		return ParsedNode{}, false
	}
	tag := decodeTag(u.Fragment)
	outbound := map[string]any{
		"type":        nodeType,
		"tag":         defaultTag(tag, nodeType, server, port),
		"server":      server,
		"server_port": port,
	}

	if u.User != nil {
		if username := strings.TrimSpace(u.User.Username()); username != "" {
			outbound["username"] = username
		}
		if password, ok := u.User.Password(); ok {
			outbound["password"] = password
		}
	}

	if scheme == "https" {
		query := u.Query()
		if !hasOnlyAllowedQueryKeys(query, "sni", "servername", "peer", "allowInsecure", "insecure") {
			return ParsedNode{}, false
		}
		tls := map[string]any{
			"enabled": true,
		}
		serverName := strings.TrimSpace(firstNonEmpty(
			query.Get("sni"),
			query.Get("servername"),
			query.Get("peer"),
			server,
		))
		if serverName != "" {
			tls["server_name"] = serverName
		}
		if queryBool(query, "allowInsecure", "insecure") {
			tls["insecure"] = true
		}
		outbound["tls"] = tls
	}

	return buildParsedNode(outbound)
}

func parseRequiredURIPort(u *url.URL) (uint64, bool) {
	port := strings.TrimSpace(u.Port())
	if port == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func isProxyURIPathAllowed(path string) bool {
	trimmed := strings.TrimSpace(path)
	return trimmed == "" || trimmed == "/"
}

func hasOnlyAllowedQueryKeys(values url.Values, allowedKeys ...string) bool {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}
	for key := range values {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(key))]; !ok {
			return false
		}
	}
	return true
}
func parseHTTPProxyIPPort(line string) (ParsedNode, bool) {
	server, port, ok := parseHostPort(line)
	if !ok || net.ParseIP(server) == nil {
		return ParsedNode{}, false
	}

	outbound := map[string]any{
		"type":        "http",
		"tag":         defaultTag("", "http", server, port),
		"server":      server,
		"server_port": port,
	}
	return buildParsedNode(outbound)
}

func parseHTTPProxyIPPortUserPass(line string) (ParsedNode, bool) {
	server, port, username, password, ok := parseIPPortUserPass(line)
	if !ok {
		return ParsedNode{}, false
	}

	outbound := map[string]any{
		"type":        "http",
		"tag":         defaultTag("", "http", server, port),
		"server":      server,
		"server_port": port,
		"username":    username,
		"password":    password,
	}
	return buildParsedNode(outbound)
}

func parseIPPortUserPass(line string) (string, uint64, string, string, bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return "", 0, "", "", false
	}

	password := strings.TrimSpace(parts[len(parts)-1])
	username := strings.TrimSpace(parts[len(parts)-2])
	portRaw := strings.TrimSpace(parts[len(parts)-3])
	hostRaw := strings.TrimSpace(strings.Join(parts[:len(parts)-3], ":"))
	if hostRaw == "" || username == "" || password == "" || portRaw == "" {
		return "", 0, "", "", false
	}

	port, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil {
		return "", 0, "", "", false
	}

	host := strings.Trim(strings.TrimSpace(hostRaw), "[]")
	if net.ParseIP(host) == nil {
		return "", 0, "", "", false
	}
	return host, port, username, password, true
}

func parseVmessURI(uri string) (ParsedNode, bool) {
	payload := strings.TrimSpace(strings.TrimPrefix(uri, "vmess://"))
	if payload == "" {
		return ParsedNode{}, false
	}

	decoded, ok := decodeBase64Relaxed(payload)
	if !ok || !utf8.Valid(decoded) {
		return ParsedNode{}, false
	}

	var v map[string]any
	if err := json.Unmarshal(decoded, &v); err != nil {
		return ParsedNode{}, false
	}

	server := strings.TrimSpace(getString(v, "add"))
	uuid := strings.TrimSpace(getString(v, "id"))
	if server == "" || uuid == "" {
		return ParsedNode{}, false
	}

	port := uint64(443)
	if parsedPort, ok := getUint(v, "port"); ok {
		port = parsedPort
	}
	tag := strings.TrimSpace(getString(v, "ps"))
	if tag == "" {
		tag = fmt.Sprintf("vmess-%s:%d", server, port)
	}
	security := strings.TrimSpace(getString(v, "scy", "security"))
	if security == "" {
		security = "auto"
	}

	outbound := map[string]any{
		"type":        "vmess",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
		"security":    security,
	}
	if alterID, ok := getUint(v, "aid", "alterId", "alter_id"); ok {
		outbound["alter_id"] = alterID
	} else {
		outbound["alter_id"] = uint64(0)
	}

	tlsValue := strings.ToLower(strings.TrimSpace(getString(v, "tls")))
	if tlsValue == "tls" || tlsValue == "1" || tlsValue == "true" {
		tls := map[string]any{"enabled": true}
		if sni := strings.TrimSpace(firstNonEmpty(getString(v, "sni"), getString(v, "host"))); sni != "" {
			tls["server_name"] = sni
		}
		outbound["tls"] = tls
	}

	network := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		getString(v, "net"),
		getString(v, "type"),
		getString(v, "network"),
	)))
	if network == "ws" {
		transport := map[string]any{"type": "ws"}
		if path := strings.TrimSpace(getString(v, "path")); path != "" {
			transport["path"] = path
		}
		if host := strings.TrimSpace(getString(v, "host")); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		outbound["transport"] = transport
	}

	return buildParsedNode(outbound)
}

func parseVlessURI(uri string) (ParsedNode, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return ParsedNode{}, false
	}
	uuid := strings.TrimSpace(u.User.Username())
	server := strings.TrimSpace(u.Hostname())
	if uuid == "" || server == "" {
		return ParsedNode{}, false
	}

	port := uriPortOrDefault(u, 443)
	tag := decodeTag(u.Fragment)
	if tag == "" {
		tag = defaultTag("", "vless", server, port)
	}

	query := u.Query()
	outbound := map[string]any{
		"type":        "vless",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"uuid":        uuid,
	}
	if flow := strings.TrimSpace(query.Get("flow")); flow != "" {
		outbound["flow"] = flow
	}

	security := strings.ToLower(strings.TrimSpace(query.Get("security")))
	sni := strings.TrimSpace(firstNonEmpty(query.Get("sni"), query.Get("servername")))
	if security == "tls" || security == "reality" || sni != "" {
		tls := map[string]any{"enabled": true}
		if sni != "" {
			tls["server_name"] = sni
		}
		outbound["tls"] = tls
	}

	network := strings.ToLower(strings.TrimSpace(firstNonEmpty(query.Get("type"), query.Get("network"))))
	if network == "ws" {
		transport := map[string]any{"type": "ws"}
		if path := strings.TrimSpace(query.Get("path")); path != "" {
			transport["path"] = path
		}
		if host := strings.TrimSpace(query.Get("host")); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		outbound["transport"] = transport
	}

	return buildParsedNode(outbound)
}

func parseTrojanURI(uri string) (ParsedNode, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return ParsedNode{}, false
	}
	password := strings.TrimSpace(u.User.Username())
	server := strings.TrimSpace(u.Hostname())
	if password == "" || server == "" {
		return ParsedNode{}, false
	}

	port := uriPortOrDefault(u, 443)
	tag := decodeTag(u.Fragment)
	if tag == "" {
		tag = defaultTag("", "trojan", server, port)
	}

	query := u.Query()
	serverName := strings.TrimSpace(firstNonEmpty(
		query.Get("sni"),
		query.Get("peer"),
		query.Get("servername"),
		server,
	))
	insecure := queryBool(query, "allowInsecure", "insecure")

	tls := map[string]any{
		"enabled":     true,
		"server_name": serverName,
	}
	if insecure {
		tls["insecure"] = true
	}

	outbound := map[string]any{
		"type":        "trojan",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls":         tls,
	}

	network := strings.ToLower(strings.TrimSpace(firstNonEmpty(query.Get("type"), query.Get("network"))))
	if network == "ws" {
		transport := map[string]any{"type": "ws"}
		if path := strings.TrimSpace(query.Get("path")); path != "" {
			transport["path"] = path
		}
		if host := strings.TrimSpace(query.Get("host")); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		outbound["transport"] = transport
	}

	return buildParsedNode(outbound)
}

func parseHysteria2URI(uri string) (ParsedNode, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return ParsedNode{}, false
	}
	password := strings.TrimSpace(u.User.Username())
	server := strings.TrimSpace(u.Hostname())
	if password == "" || server == "" {
		return ParsedNode{}, false
	}

	port := uriPortOrDefault(u, 443)
	tag := decodeTag(u.Fragment)
	if tag == "" {
		tag = defaultTag("", "hysteria2", server, port)
	}

	query := u.Query()
	serverName := strings.TrimSpace(firstNonEmpty(
		query.Get("sni"),
		query.Get("peer"),
		query.Get("servername"),
		server,
	))
	tls := map[string]any{
		"enabled":     true,
		"server_name": serverName,
	}
	if queryBool(query, "insecure", "allowInsecure") {
		tls["insecure"] = true
	}
	if alpn := splitALPN(query.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}

	outbound := map[string]any{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"password":    password,
		"tls":         tls,
	}
	return buildParsedNode(outbound)
}

func parseSSURI(uri string) (ParsedNode, bool) {
	raw := strings.TrimSpace(strings.TrimPrefix(uri, "ss://"))
	if raw == "" {
		return ParsedNode{}, false
	}

	beforeFragment, fragment, _ := strings.Cut(raw, "#")
	beforeQuery, _, _ := strings.Cut(beforeFragment, "?")
	tag := decodeTag(fragment)
	if tag == "" {
		tag = "shadowsocks"
	}

	if at := strings.LastIndex(beforeQuery, "@"); at > 0 && at < len(beforeQuery)-1 {
		left := beforeQuery[:at]
		hostport := beforeQuery[at+1:]
		method, password, ok := parseSSMethodPassword(left)
		if !ok {
			return ParsedNode{}, false
		}
		server, port, ok := parseHostPort(hostport)
		if !ok {
			return ParsedNode{}, false
		}
		outbound := map[string]any{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      server,
			"server_port": port,
			"method":      method,
			"password":    password,
		}
		return buildParsedNode(outbound)
	}

	decoded, ok := decodeBase64Relaxed(beforeQuery)
	if !ok || !utf8.Valid(decoded) {
		return ParsedNode{}, false
	}
	decodedText := string(decoded)
	at := strings.LastIndex(decodedText, "@")
	if at <= 0 || at >= len(decodedText)-1 {
		return ParsedNode{}, false
	}
	left := decodedText[:at]
	hostport := decodedText[at+1:]
	method, password, ok := parseSSMethodPassword(left)
	if !ok {
		return ParsedNode{}, false
	}
	server, port, ok := parseHostPort(hostport)
	if !ok {
		return ParsedNode{}, false
	}

	outbound := map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	return buildParsedNode(outbound)
}

func parseSSMethodPassword(input string) (string, string, bool) {
	if method, password, ok := strings.Cut(input, ":"); ok {
		method = strings.TrimSpace(method)
		password = strings.TrimSpace(password)
		if method != "" && password != "" {
			return method, password, true
		}
	}

	decoded, ok := decodeBase64Relaxed(strings.TrimSpace(input))
	if !ok || !utf8.Valid(decoded) {
		return "", "", false
	}
	method, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	method = strings.TrimSpace(method)
	password = strings.TrimSpace(password)
	if method == "" || password == "" {
		return "", "", false
	}
	return method, password, true
}

func parseHostPort(hostport string) (string, uint64, bool) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, false
	}

	if host, port, err := net.SplitHostPort(hostport); err == nil {
		parsedPort, parseErr := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
		if parseErr != nil {
			return "", 0, false
		}
		host = strings.TrimSpace(strings.Trim(host, "[]"))
		if host == "" {
			return "", 0, false
		}
		return host, parsedPort, true
	}

	idx := strings.LastIndex(hostport, ":")
	if idx <= 0 || idx >= len(hostport)-1 {
		return "", 0, false
	}
	host := strings.TrimSpace(strings.Trim(hostport[:idx], "[]"))
	if host == "" {
		return "", 0, false
	}
	parsedPort, err := strconv.ParseUint(strings.TrimSpace(hostport[idx+1:]), 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, parsedPort, true
}

func decodeBase64Relaxed(input string) ([]byte, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, false
	}

	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, true
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, true
	}
	return nil, false
}

func tryDecodeBase64ToText(data []byte) (string, bool) {
	compact := strings.Join(strings.Fields(string(data)), "")
	if !looksLikeBase64(compact) {
		return "", false
	}

	decoded, ok := decodeBase64Relaxed(compact)
	if !ok || !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

func looksLikeBase64(s string) bool {
	if len(s) < 24 || len(s)%4 == 1 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '-' || r == '_' || r == '=':
		default:
			return false
		}
	}
	return true
}

func looksLikeJSON(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	switch data[0] {
	case '{':
		return true
	case '[':
		// Avoid misclassifying bracketed IPv6 proxy lines like:
		// [2001:db8::1]:8080
		idx := 1
		for idx < len(data) {
			switch data[idx] {
			case ' ', '\t', '\r', '\n':
				idx++
				continue
			case '{', ']':
				return true
			default:
				return false
			}
		}
		return false
	default:
		return false
	}
}

func looksLikeClashYAML(text string) bool {
	lower := strings.ToLower(text)
	return strings.HasPrefix(lower, "proxies:") ||
		strings.Contains(lower, "\nproxies:") ||
		strings.HasPrefix(lower, "proxy-groups:") ||
		strings.Contains(lower, "\nproxy-groups:")
}

func setTLSFromClash(outbound map[string]any, proxy map[string]any, key string) {
	enabled, ok := getBool(proxy, key)
	if !ok || !enabled {
		return
	}
	tls := map[string]any{"enabled": true}
	if serverName := strings.TrimSpace(firstNonEmpty(
		getString(proxy, "servername"),
		getString(proxy, "sni"),
		getString(proxy, "peer"),
	)); serverName != "" {
		tls["server_name"] = serverName
	}
	if insecure, ok := getBool(proxy, "skip-cert-verify", "insecure", "allowInsecure"); ok && insecure {
		tls["insecure"] = true
	}
	outbound["tls"] = tls
}

func setWSTransportFromClash(outbound map[string]any, proxy map[string]any) {
	if strings.ToLower(strings.TrimSpace(getString(proxy, "network"))) != "ws" {
		return
	}
	transport := map[string]any{"type": "ws"}
	if wsOpts, ok := getMap(proxy, "ws-opts", "ws_opts"); ok {
		if path := strings.TrimSpace(getString(wsOpts, "path")); path != "" {
			transport["path"] = path
		}
		if headers, ok := getMap(wsOpts, "headers"); ok && len(headers) > 0 {
			transport["headers"] = headers
		}
	}
	outbound["transport"] = transport
}

func buildParsedNode(outbound map[string]any) (ParsedNode, bool) {
	raw, err := json.Marshal(outbound)
	if err != nil {
		return ParsedNode{}, false
	}
	var header outboundHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return ParsedNode{}, false
	}
	if !supportedOutboundTypes[header.Type] {
		return ParsedNode{}, false
	}
	return ParsedNode{
		Tag:        header.Tag,
		RawOptions: json.RawMessage(raw),
	}, true
}

func normalizeInput(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	return bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
}

func normalizeTextContent(content string) string {
	content = strings.TrimPrefix(content, "\uFEFF")

	var b strings.Builder
	b.Grow(len(content))
	for _, r := range content {
		switch r {
		case '\u200B', '\u200C', '\u200D':
			continue
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func getString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			return t
		case json.Number:
			return t.String()
		case int:
			return strconv.Itoa(t)
		case int8:
			return strconv.FormatInt(int64(t), 10)
		case int16:
			return strconv.FormatInt(int64(t), 10)
		case int32:
			return strconv.FormatInt(int64(t), 10)
		case int64:
			return strconv.FormatInt(t, 10)
		case uint:
			return strconv.FormatUint(uint64(t), 10)
		case uint8:
			return strconv.FormatUint(uint64(t), 10)
		case uint16:
			return strconv.FormatUint(uint64(t), 10)
		case uint32:
			return strconv.FormatUint(uint64(t), 10)
		case uint64:
			return strconv.FormatUint(t, 10)
		case float32:
			return strconv.FormatFloat(float64(t), 'f', -1, 64)
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(t)
		}
	}
	return ""
}

func getUint(m map[string]any, keys ...string) (uint64, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case int:
			if t >= 0 {
				return uint64(t), true
			}
		case int8:
			if t >= 0 {
				return uint64(t), true
			}
		case int16:
			if t >= 0 {
				return uint64(t), true
			}
		case int32:
			if t >= 0 {
				return uint64(t), true
			}
		case int64:
			if t >= 0 {
				return uint64(t), true
			}
		case uint:
			return uint64(t), true
		case uint8:
			return uint64(t), true
		case uint16:
			return uint64(t), true
		case uint32:
			return uint64(t), true
		case uint64:
			return t, true
		case float32:
			if t >= 0 {
				return uint64(t), true
			}
		case float64:
			if t >= 0 {
				return uint64(t), true
			}
		case string:
			parsed, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
			if err == nil {
				return parsed, true
			}
		case json.Number:
			parsed, err := strconv.ParseUint(t.String(), 10, 64)
			if err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func getBool(m map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t, true
		case string:
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "1", "true", "yes", "on":
				return true, true
			case "0", "false", "no", "off":
				return false, true
			}
		}
	}
	return false, false
}

func getMap(m map[string]any, keys ...string) (map[string]any, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			return t, true
		case map[any]any:
			converted := make(map[string]any, len(t))
			for mk, mv := range t {
				converted[fmt.Sprint(mk)] = mv
			}
			return converted, true
		}
	}
	return nil, false
}

func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}

	switch t := v.(type) {
	case string:
		return splitALPN(t)
	case []string:
		var out []string
		for _, item := range t {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	default:
		return nil
	}
}

func getStringList(m map[string]any, keys ...string) []string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		if values := parseStringListValue(v); len(values) > 0 {
			return values
		}
	}
	return nil
}

func parseStringListValue(value any) []string {
	switch t := value.(type) {
	case string:
		return splitCommaList(t)
	case []string:
		out := make([]string, 0, len(t))
		for _, item := range t {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func getUint8Array(m map[string]any, keys ...string) ([]int, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case []any:
			values := make([]int, 0, len(t))
			for _, item := range t {
				uint8Value, ok := parseUint8(item)
				if !ok {
					values = nil
					break
				}
				values = append(values, uint8Value)
			}
			if len(values) > 0 {
				return values, true
			}
		case []int:
			values := make([]int, 0, len(t))
			valid := true
			for _, item := range t {
				if item < 0 || item > 255 {
					valid = false
					break
				}
				values = append(values, item)
			}
			if valid && len(values) > 0 {
				return values, true
			}
		}
	}
	return nil, false
}

func parseUint8(raw any) (int, bool) {
	switch t := raw.(type) {
	case int:
		if t >= 0 && t <= 255 {
			return t, true
		}
	case int8:
		if t >= 0 {
			return int(t), true
		}
	case int16:
		if t >= 0 && t <= 255 {
			return int(t), true
		}
	case int32:
		if t >= 0 && t <= 255 {
			return int(t), true
		}
	case int64:
		if t >= 0 && t <= 255 {
			return int(t), true
		}
	case uint:
		if t <= 255 {
			return int(t), true
		}
	case uint8:
		return int(t), true
	case uint16:
		if t <= 255 {
			return int(t), true
		}
	case uint32:
		if t <= 255 {
			return int(t), true
		}
	case uint64:
		if t <= 255 {
			return int(t), true
		}
	case float32:
		if t >= 0 && t <= 255 && float32(int(t)) == t {
			return int(t), true
		}
	case float64:
		if t >= 0 && t <= 255 && float64(int(t)) == t {
			return int(t), true
		}
	case json.Number:
		value, err := strconv.ParseInt(t.String(), 10, 64)
		if err == nil && value >= 0 && value <= 255 {
			return int(value), true
		}
	case string:
		value, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err == nil && value >= 0 && value <= 255 {
			return int(value), true
		}
	}
	return 0, false
}

func queryBool(values url.Values, keys ...string) bool {
	for _, key := range keys {
		value := strings.TrimSpace(values.Get(key))
		if value == "" {
			continue
		}
		switch strings.ToLower(value) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func splitALPN(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func decodeTag(fragment string) string {
	if fragment == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(fragment)
	if err != nil {
		return strings.TrimSpace(fragment)
	}
	return strings.TrimSpace(decoded)
}

func uriPortOrDefault(u *url.URL, fallback uint64) uint64 {
	port := strings.TrimSpace(u.Port())
	if port == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fallback
	}
	return parsed
}

func defaultTag(tag string, proto string, server string, port uint64) string {
	if trimmed := strings.TrimSpace(tag); trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("%s-%s:%d", proto, server, port)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
