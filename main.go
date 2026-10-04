package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28

	dnsClassIN = 1

	flagQR = 0x8000
	flagTC = 0x0200
	flagRD = 0x0100
)

type Config struct {
	Name       string
	QueryType  uint16
	Timeout    time.Duration
	Attempts   int
	Resolver   string
	Compare    bool
	ShowConfig bool
	TCPOnly    bool
}

type ResolvConfig struct {
	Path        string
	Nameservers []string
	Search      []string
	Options     []string
	SortList    []string
	Domain      string
	IsSymlink   bool
	LinkTarget  string
	Stub        bool
	StubReason  string
}

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

type DNSResponse struct {
	Header      DNSHeader
	Answers     []DNSRecord
	Authorities []DNSRecord
	Additionals []DNSRecord
	RCode       int
	Truncated   bool
	RawSize     int
}

type QueryResult struct {
	Resolver  string
	Protocol  string
	Latency   time.Duration
	Response  DNSResponse
	Error     error
	Attempt   int
	Timestamp time.Time
}

type ResolverSummary struct {
	Resolver    string
	Success     int
	Failure     int
	Min         time.Duration
	Max         time.Duration
	Average     time.Duration
	Answers     []string
	LastRCode   int
	LastError   string
	Protocols   []string
	Measurements []QueryResult
}

var transactionID uint32 = uint32(time.Now().UnixNano())

func main() {
	config := parseFlags()

	if config.ShowConfig {
		printResolvInspection()
	}

	resolvers := determineResolvers(config)

	if len(resolvers) == 0 {
		fatal("no DNS resolvers available")
	}

	fmt.Println()
	fmt.Println("DNS FORENSICS")
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("Target      : %s\n", config.Name)
	fmt.Printf("Record type : %s\n", typeName(config.QueryType))
	fmt.Printf("Timeout     : %s\n", config.Timeout)
	fmt.Printf("Attempts    : %d\n", config.Attempts)

	if config.TCPOnly {
		fmt.Println("Transport   : TCP")
	} else {
		fmt.Println("Transport   : UDP with TCP fallback")
	}

	fmt.Printf("Resolvers   : %s\n", strings.Join(resolvers, ", "))

	results := queryResolvers(
		resolvers,
		config.Name,
		config.QueryType,
		config.Attempts,
		config.Timeout,
		config.TCPOnly,
	)

	summaries := summarizeResults(resolvers, results)

	printMeasurements(results)
	printResolverSummaries(summaries)

	if config.Compare && len(summaries) > 1 {
		printComparison(summaries)
	}
}

func parseFlags() Config {
	var config Config
	var queryType string

	flag.StringVar(
		&config.Name,
		"name",
		"example.com",
		"DNS name to query",
	)

	flag.StringVar(
		&queryType,
		"type",
		"A",
		"record type: A, AAAA, NS, CNAME, MX, TXT, PTR, SOA",
	)

	flag.DurationVar(
		&config.Timeout,
		"timeout",
		3*time.Second,
		"timeout for each DNS request",
	)

	flag.IntVar(
		&config.Attempts,
		"attempts",
		3,
		"number of queries per resolver",
	)

	flag.StringVar(
		&config.Resolver,
		"resolver",
		"",
		"query only this resolver",
	)

	flag.BoolVar(
		&config.Compare,
		"compare",
		true,
		"compare answers returned by multiple resolvers",
	)

	flag.BoolVar(
		&config.ShowConfig,
		"config",
		true,
		"inspect resolver configuration",
	)

	flag.BoolVar(
		&config.TCPOnly,
		"tcp",
		false,
		"use TCP instead of UDP",
	)

	flag.Usage = func() {
		out := flag.CommandLine.Output()

		fmt.Fprintln(out, "dns-forensics - Linux DNS configuration and resolver diagnostics")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  dns-forensics [options]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  dns-forensics")
		fmt.Fprintln(out, "  dns-forensics -name kernel.org")
		fmt.Fprintln(out, "  dns-forensics -name kernel.org -type AAAA")
		fmt.Fprintln(out, "  dns-forensics -name example.com -resolver 1.1.1.1")
		fmt.Fprintln(out, "  dns-forensics -name example.com -attempts 5")
		fmt.Fprintln(out, "  dns-forensics -name example.com -tcp")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")

		flag.PrintDefaults()
	}

	flag.Parse()

	config.Name = strings.TrimSpace(config.Name)

	if config.Name == "" {
		fatal("query name cannot be empty")
	}

	config.Name = strings.TrimSuffix(config.Name, ".")

	if config.Attempts < 1 {
		config.Attempts = 1
	}

	if config.Attempts > 100 {
		config.Attempts = 100
	}

	if config.Timeout <= 0 {
		config.Timeout = 3 * time.Second
	}

	var err error

	config.QueryType, err = parseQueryType(queryType)
	if err != nil {
		fatal("%v", err)
	}

	return config
}

func parseQueryType(value string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "A":
		return dnsTypeA, nil
	case "NS":
		return dnsTypeNS, nil
	case "CNAME":
		return dnsTypeCNAME, nil
	case "SOA":
		return dnsTypeSOA, nil
	case "PTR":
		return dnsTypePTR, nil
	case "MX":
		return dnsTypeMX, nil
	case "TXT":
		return dnsTypeTXT, nil
	case "AAAA":
		return dnsTypeAAAA, nil
	default:
		return 0, fmt.Errorf("unsupported DNS type %q", value)
	}
}

func printResolvInspection() {
	fmt.Println("RESOLVER CONFIGURATION")
	fmt.Println(strings.Repeat("=", 78))

	paths := []string{
		"/etc/resolv.conf",
		"/run/systemd/resolve/stub-resolv.conf",
		"/run/systemd/resolve/resolv.conf",
	}

	found := false

	for _, path := range paths {
		config, err := inspectResolvConf(path)
		if err != nil {
			continue
		}

		found = true
		printResolvConfig(config)
	}

	if !found {
		fmt.Println("No readable resolver configuration found.")
	}

	printSystemdResolvedStatus()
}

func inspectResolvConf(path string) (ResolvConfig, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ResolvConfig{}, err
	}

	config := ResolvConfig{
		Path: path,
	}

	if info.Mode()&os.ModeSymlink != 0 {
		config.IsSymlink = true

		target, err := os.Readlink(path)
		if err == nil {
			config.LinkTarget = target
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return ResolvConfig{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			config.Nameservers = append(
				config.Nameservers,
				normalizeResolver(fields[1]),
			)

		case "search":
			config.Search = append(config.Search, fields[1:]...)

		case "domain":
			config.Domain = fields[1]

		case "options":
			config.Options = append(config.Options, fields[1:]...)

		case "sortlist":
			config.SortList = append(config.SortList, fields[1:]...)
		}
	}

	if err := scanner.Err(); err != nil {
		return ResolvConfig{}, err
	}

	config.Stub, config.StubReason = detectStub(config)

	return config, nil
}

func detectStub(config ResolvConfig) (bool, string) {
	for _, resolver := range config.Nameservers {
		host := resolverHost(resolver)

		switch host {
		case "127.0.0.53":
			return true, "systemd-resolved stub address 127.0.0.53"

		case "127.0.0.54":
			return true, "systemd-resolved proxy/stub address 127.0.0.54"

		case "127.0.0.1", "::1":
			return true, "loopback DNS resolver"
		}
	}

	if strings.Contains(config.LinkTarget, "stub-resolv.conf") {
		return true, "resolv.conf points to systemd-resolved stub configuration"
	}

	return false, ""
}

func printResolvConfig(config ResolvConfig) {
	fmt.Println()
	fmt.Printf("File        : %s\n", config.Path)

	if config.IsSymlink {
		fmt.Printf("Symlink     : %s\n", config.LinkTarget)

		if resolved, err := filepath.EvalSymlinks(config.Path); err == nil {
			fmt.Printf("Resolved    : %s\n", resolved)
		}
	}

	if len(config.Nameservers) == 0 {
		fmt.Println("Nameservers : none")
	} else {
		fmt.Printf(
			"Nameservers : %s\n",
			strings.Join(config.Nameservers, ", "),
		)
	}

	if len(config.Search) > 0 {
		fmt.Printf("Search      : %s\n", strings.Join(config.Search, ", "))
	}

	if config.Domain != "" {
		fmt.Printf("Domain      : %s\n", config.Domain)
	}

	if len(config.Options) > 0 {
		fmt.Printf("Options     : %s\n", strings.Join(config.Options, ", "))
	}

	if len(config.SortList) > 0 {
		fmt.Printf("Sort list   : %s\n", strings.Join(config.SortList, ", "))
	}

	if config.Stub {
		fmt.Printf("Stub        : yes (%s)\n", config.StubReason)
	} else {
		fmt.Println("Stub        : no")
	}
}

func printSystemdResolvedStatus() {
	fmt.Println()
	fmt.Println("STUB RESOLVER ANALYSIS")

	mainConfig, err := inspectResolvConf("/etc/resolv.conf")
	if err != nil {
		fmt.Println("Unable to inspect /etc/resolv.conf.")
		return
	}

	if !mainConfig.Stub {
		fmt.Println("No obvious local stub resolver detected.")
		return
	}

	fmt.Printf("Detected    : %s\n", mainConfig.StubReason)

	upstream, err := inspectResolvConf("/run/systemd/resolve/resolv.conf")
	if err != nil || len(upstream.Nameservers) == 0 {
		fmt.Println("Upstream    : not discovered from systemd-resolved")
		return
	}

	fmt.Printf(
		"Upstream    : %s\n",
		strings.Join(upstream.Nameservers, ", "),
	)
}

func determineResolvers(config Config) []string {
	if config.Resolver != "" {
		return []string{normalizeResolver(config.Resolver)}
	}

	mainConfig, err := inspectResolvConf("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	var resolvers []string

	resolvers = append(resolvers, mainConfig.Nameservers...)

	if mainConfig.Stub {
		upstream, err := inspectResolvConf("/run/systemd/resolve/resolv.conf")
		if err == nil {
			resolvers = append(resolvers, upstream.Nameservers...)
		}
	}

	return uniqueStrings(resolvers)
}

func queryResolvers(
	resolvers []string,
	name string,
	queryType uint16,
	attempts int,
	timeout time.Duration,
	tcpOnly bool,
) []QueryResult {
	var wg sync.WaitGroup
	results := make(chan QueryResult, len(resolvers)*attempts)

	for _, resolver := range resolvers {
		for attempt := 1; attempt <= attempts; attempt++ {
			wg.Add(1)

			go func(resolver string, attempt int) {
				defer wg.Done()

				result := queryResolver(
					resolver,
					name,
					queryType,
					timeout,
					tcpOnly,
				)

				result.Attempt = attempt
				results <- result
			}(resolver, attempt)
		}
	}

	wg.Wait()
	close(results)

	var collected []QueryResult

	for result := range results {
		collected = append(collected, result)
	}

	sort.Slice(collected, func(i, j int) bool {
		if collected[i].Resolver == collected[j].Resolver {
			return collected[i].Attempt < collected[j].Attempt
		}

		return collected[i].Resolver < collected[j].Resolver
	})

	return collected
}

func queryResolver(
	resolver string,
	name string,
	queryType uint16,
	timeout time.Duration,
	tcpOnly bool,
) QueryResult {
	result := QueryResult{
		Resolver:  resolver,
		Timestamp: time.Now(),
	}

	message, id, err := buildQuery(name, queryType)
	if err != nil {
		result.Error = err
		return result
	}

	address := resolverAddress(resolver)

	if tcpOnly {
		start := time.Now()

		data, err := exchangeTCP(address, message, timeout)

		result.Latency = time.Since(start)
		result.Protocol = "TCP"

		if err != nil {
			result.Error = err
			return result
		}

		response, err := parseDNSResponse(data, id)

		result.Response = response
		result.Error = err

		return result
	}

	start := time.Now()

	data, err := exchangeUDP(address, message, timeout)

	result.Latency = time.Since(start)
	result.Protocol = "UDP"

	if err != nil {
		result.Error = err
		return result
	}

	response, err := parseDNSResponse(data, id)
	if err != nil {
		result.Error = err
		return result
	}

	if response.Truncated {
		start = time.Now()

		data, err = exchangeTCP(address, message, timeout)

		result.Latency = time.Since(start)
		result.Protocol = "TCP"

		if err != nil {
			result.Error = err
			return result
		}

		response, err = parseDNSResponse(data, id)
		if err != nil {
			result.Error = err
			return result
		}
	}

	result.Response = response

	return result
}

func buildQuery(name string, queryType uint16) ([]byte, uint16, error) {
	id := uint16(atomic.AddUint32(&transactionID, 1))

	var buffer bytes.Buffer

	header := DNSHeader{
		ID:      id,
		Flags:   flagRD,
		QDCount: 1,
	}

	if err := binary.Write(&buffer, binary.BigEndian, header.ID); err != nil {
		return nil, 0, err
	}

	if err := binary.Write(&buffer, binary.BigEndian, header.Flags); err != nil {
		return nil, 0, err
	}

	if err := binary.Write(&buffer, binary.BigEndian, header.QDCount); err != nil {
		return nil, 0, err
	}

	for i := 0; i < 3; i++ {
		if err := binary.Write(&buffer, binary.BigEndian, uint16(0)); err != nil {
			return nil, 0, err
		}
	}

	encodedName, err := encodeDNSName(name)
	if err != nil {
		return nil, 0, err
	}

	buffer.Write(encodedName)

	if err := binary.Write(&buffer, binary.BigEndian, queryType); err != nil {
		return nil, 0, err
	}

	if err := binary.Write(&buffer, binary.BigEndian, uint16(dnsClassIN)); err != nil {
		return nil, 0, err
	}

	return buffer.Bytes(), id, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")

	if name == "" {
		return []byte{0}, nil
	}

	var buffer bytes.Buffer

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, errors.New("invalid empty DNS label")
		}

		if len(label) > 63 {
			return nil, errors.New("DNS label exceeds 63 bytes")
		}

		buffer.WriteByte(byte(len(label)))
		buffer.WriteString(label)
	}

	buffer.WriteByte(0)

	if buffer.Len() > 255 {
		return nil, errors.New("DNS name exceeds 255 bytes")
	}

	return buffer.Bytes(), nil
}

func exchangeUDP(address string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buffer := make([]byte, 65535)

	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return append([]byte(nil), buffer[:n]...), nil
}

func exchangeTCP(address string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if len(query) > 65535 {
		return nil, errors.New("DNS query too large for TCP framing")
	}

	length := []byte{
		byte(len(query) >> 8),
		byte(len(query)),
	}

	if _, err := conn.Write(length); err != nil {
		return nil, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	size := int(binary.BigEndian.Uint16(header))

	if size < 12 {
		return nil, errors.New("invalid DNS TCP response size")
	}

	data := make([]byte, size)

	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func parseDNSResponse(data []byte, expectedID uint16) (DNSResponse, error) {
	if len(data) < 12 {
		return DNSResponse{}, errors.New("DNS response is shorter than header")
	}

	response := DNSResponse{
		Header: DNSHeader{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			Flags:   binary.BigEndian.Uint16(data[2:4]),
			QDCount: binary.BigEndian.Uint16(data[4:6]),
			ANCount: binary.BigEndian.Uint16(data[6:8]),
			NSCount: binary.BigEndian.Uint16(data[8:10]),
			ARCount: binary.BigEndian.Uint16(data[10:12]),
		},
		RawSize: len(data),
	}

	if response.Header.ID != expectedID {
		return response, fmt.Errorf(
			"transaction ID mismatch: expected %d, received %d",
			expectedID,
			response.Header.ID,
		)
	}

	if response.Header.Flags&flagQR == 0 {
		return response, errors.New("received packet is not a DNS response")
	}

	response.RCode = int(response.Header.Flags & 0x000f)
	response.Truncated = response.Header.Flags&flagTC != 0

	offset := 12

	for i := 0; i < int(response.Header.QDCount); i++ {
		_, next, err := decodeDNSName(data, offset)
		if err != nil {
			return response, err
		}

		offset = next

		if offset+4 > len(data) {
			return response, errors.New("truncated DNS question")
		}

		offset += 4
	}

	var err error

	response.Answers, offset, err = parseRecords(
		data,
		offset,
		int(response.Header.ANCount),
	)
	if err != nil {
		return response, err
	}

	response.Authorities, offset, err = parseRecords(
		data,
		offset,
		int(response.Header.NSCount),
	)
	if err != nil {
		return response, err
	}

	response.Additionals, _, err = parseRecords(
		data,
		offset,
		int(response.Header.ARCount),
	)
	if err != nil {
		return response, err
	}

	return response, nil
}

func parseRecords(
	data []byte,
	offset int,
	count int,
) ([]DNSRecord, int, error) {
	records := make([]DNSRecord, 0, count)

	for i := 0; i < count; i++ {
		name, next, err := decodeDNSName(data, offset)
		if err != nil {
			return nil, offset, err
		}

		offset = next

		if offset+10 > len(data) {
			return nil, offset, errors.New("truncated DNS resource record")
		}

		recordType := binary.BigEndian.Uint16(data[offset : offset+2])
		class := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))

		offset += 10

		if offset+rdLength > len(data) {
			return nil, offset, errors.New("truncated DNS RDATA")
		}

		value, err := decodeRData(
			data,
			offset,
			rdLength,
			recordType,
		)
		if err != nil {
			value = fmt.Sprintf("<decode error: %v>", err)
		}

		records = append(records, DNSRecord{
			Name:  name,
			Type:  recordType,
			Class: class,
			TTL:   ttl,
			Data:  value,
		})

		offset += rdLength
	}

	return records, offset, nil
}

func decodeRData(
	data []byte,
	offset int,
	length int,
	recordType uint16,
) (string, error) {
	end := offset + length

	if end > len(data) {
		return "", errors.New("RDATA exceeds packet")
	}

	switch recordType {
	case dnsTypeA:
		if length != 4 {
			return "", errors.New("invalid A record length")
		}

		return net.IP(data[offset:end]).String(), nil

	case dnsTypeAAAA:
		if length != 16 {
			return "", errors.New("invalid AAAA record length")
		}

		return net.IP(data[offset:end]).String(), nil

	case dnsTypeNS, dnsTypeCNAME, dnsTypePTR:
		name, _, err := decodeDNSName(data, offset)
		return name, err

	case dnsTypeMX:
		if length < 3 {
			return "", errors.New("invalid MX record")
		}

		preference := binary.BigEndian.Uint16(data[offset : offset+2])

		host, _, err := decodeDNSName(data, offset+2)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%d %s", preference, host), nil

	case dnsTypeTXT:
		var values []string
		position := offset

		for position < end {
			size := int(data[position])
			position++

			if position+size > end {
				return "", errors.New("invalid TXT string")
			}

			values = append(
				values,
				strconv.Quote(string(data[position:position+size])),
			)

			position += size
		}

		return strings.Join(values, " "), nil

	case dnsTypeSOA:
		mname, next, err := decodeDNSName(data, offset)
		if err != nil {
			return "", err
		}

		rname, next, err := decodeDNSName(data, next)
		if err != nil {
			return "", err
		}

		if next+20 > end {
			return "", errors.New("invalid SOA record")
		}

		serial := binary.BigEndian.Uint32(data[next : next+4])
		refresh := binary.BigEndian.Uint32(data[next+4 : next+8])
		retry := binary.BigEndian.Uint32(data[next+8 : next+12])
		expire := binary.BigEndian.Uint32(data[next+12 : next+16])
		minimum := binary.BigEndian.Uint32(data[next+16 : next+20])

		return fmt.Sprintf(
			"%s %s serial=%d refresh=%d retry=%d expire=%d minimum=%d",
			mname,
			rname,
			serial,
			refresh,
			retry,
			expire,
			minimum,
		), nil

	default:
		return formatHex(data[offset:end]), nil
	}
}

func decodeDNSName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, errors.New("DNS name offset outside packet")
	}

	var labels []string
	position := offset
	nextOffset := -1
	jumps := 0

	for {
		if position >= len(data) {
			return "", offset, errors.New("DNS name exceeds packet")
		}

		length := int(data[position])

		if length&0xc0 == 0xc0 {
			if position+1 >= len(data) {
				return "", offset, errors.New("truncated DNS compression pointer")
			}

			pointer := ((length & 0x3f) << 8) | int(data[position+1])

			if pointer >= len(data) {
				return "", offset, errors.New("DNS compression pointer outside packet")
			}

			if nextOffset == -1 {
				nextOffset = position + 2
			}

			position = pointer
			jumps++

			if jumps > 32 {
				return "", offset, errors.New("excessive DNS compression pointers")
			}

			continue
		}

		if length&0xc0 != 0 {
			return "", offset, errors.New("unsupported DNS label encoding")
		}

		position++

		if length == 0 {
			if nextOffset == -1 {
				nextOffset = position
			}

			break
		}

		if length > 63 {
			return "", offset, errors.New("DNS label exceeds 63 bytes")
		}

		if position+length > len(data) {
			return "", offset, errors.New("DNS label exceeds packet")
		}

		labels = append(
			labels,
			string(data[position:position+length]),
		)

		position += length
	}

	name := strings.Join(labels, ".")

	if name == "" {
		name = "."
	}

	return name, nextOffset, nil
}

func summarizeResults(
	resolvers []string,
	results []QueryResult,
) []ResolverSummary {
	summaries := make([]ResolverSummary, 0, len(resolvers))

	for _, resolver := range resolvers {
		summary := ResolverSummary{
			Resolver: resolver,
		}

		var total time.Duration
		protocols := make(map[string]struct{})
		answers := make(map[string]struct{})

		for _, result := range results {
			if result.Resolver != resolver {
				continue
			}

			summary.Measurements = append(summary.Measurements, result)

			if result.Protocol != "" {
				protocols[result.Protocol] = struct{}{}
			}

			if result.Error != nil {
				summary.Failure++
				summary.LastError = result.Error.Error()
				continue
			}

			summary.Success++
			total += result.Latency
			summary.LastRCode = result.Response.RCode

			if summary.Min == 0 || result.Latency < summary.Min {
				summary.Min = result.Latency
			}

			if result.Latency > summary.Max {
				summary.Max = result.Latency
			}

			for _, record := range result.Response.Answers {
				answers[recordIdentity(record)] = struct{}{}
			}
		}

		if summary.Success > 0 {
			summary.Average = total / time.Duration(summary.Success)
		}

		for protocol := range protocols {
			summary.Protocols = append(summary.Protocols, protocol)
		}

		for answer := range answers {
			summary.Answers = append(summary.Answers, answer)
		}

		sort.Strings(summary.Protocols)
		sort.Strings(summary.Answers)

		summaries = append(summaries, summary)
	}

	return summaries
}

func printMeasurements(results []QueryResult) {
	fmt.Println()
	fmt.Println("MEASUREMENTS")

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(
		writer,
		"RESOLVER\tTRY\tPROTO\tLATENCY\tRCODE\tANSWERS\tSTATUS",
	)

	for _, result := range results {
		if result.Error != nil {
			fmt.Fprintf(
				writer,
				"%s\t%d\t%s\t%s\t-\t-\t%s\n",
				result.Resolver,
				result.Attempt,
				emptyDash(result.Protocol),
				formatDuration(result.Latency),
				truncate(result.Error.Error(), 48),
			)

			continue
		}

		fmt.Fprintf(
			writer,
			"%s\t%d\t%s\t%s\t%s\t%d\tOK\n",
			result.Resolver,
			result.Attempt,
			result.Protocol,
			formatDuration(result.Latency),
			rcodeName(result.Response.RCode),
			len(result.Response.Answers),
		)
	}

	writer.Flush()
}

func printResolverSummaries(summaries []ResolverSummary) {
	fmt.Println()
	fmt.Println("RESOLVER SUMMARY")

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(
		writer,
		"RESOLVER\tSUCCESS\tFAIL\tMIN\tAVG\tMAX\tPROTO\tRCODE",
	)

	for _, summary := range summaries {
		fmt.Fprintf(
			writer,
			"%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			summary.Resolver,
			summary.Success,
			summary.Failure,
			formatDuration(summary.Min),
			formatDuration(summary.Average),
			formatDuration(summary.Max),
			emptyDash(strings.Join(summary.Protocols, ",")),
			rcodeName(summary.LastRCode),
		)
	}

	writer.Flush()

	for _, summary := range summaries {
		fmt.Println()
		fmt.Printf("Resolver %s\n", summary.Resolver)

		if len(summary.Answers) == 0 {
			fmt.Println("  Answers: none")

			if summary.LastError != "" {
				fmt.Printf(
					"  Error  : %s\n",
					truncate(summary.LastError, 100),
				)
			}

			continue
		}

		for _, answer := range summary.Answers {
			fmt.Printf("  %s\n", answer)
		}
	}
}

func printComparison(summaries []ResolverSummary) {
	fmt.Println()
	fmt.Println("RESOLVER COMPARISON")

	successful := make([]ResolverSummary, 0, len(summaries))

	for _, summary := range summaries {
		if summary.Success > 0 {
			successful = append(successful, summary)
		}
	}

	if len(successful) < 2 {
		fmt.Println("Not enough successful resolvers for comparison.")
		return
	}

	allSame := true

	base := answerSignature(successful[0].Answers)

	for _, summary := range successful[1:] {
		if answerSignature(summary.Answers) != base {
			allSame = false
			break
		}
	}

	if allSame {
		fmt.Println("Answer sets  : consistent")
	} else {
		fmt.Println("Answer sets  : differ")
	}

	fastest := successful[0]

	for _, summary := range successful[1:] {
		if summary.Average > 0 &&
			(fastest.Average == 0 || summary.Average < fastest.Average) {
			fastest = summary
		}
	}

	fmt.Printf(
		"Fastest avg  : %s (%s)\n",
		fastest.Resolver,
		formatDuration(fastest.Average),
	)

	for _, summary := range successful {
		fmt.Printf(
			"%-12s : avg %s, %d unique answers\n",
			summary.Resolver,
			formatDuration(summary.Average),
			len(summary.Answers),
		)
	}
}

func recordIdentity(record DNSRecord) string {
	return fmt.Sprintf(
		"%s %d %s %s",
		record.Name,
		record.TTL,
		typeName(record.Type),
		record.Data,
	)
}

func answerSignature(answers []string) string {
	values := append([]string(nil), answers...)
	sort.Strings(values)

	return strings.Join(values, "\x00")
}

func resolverAddress(resolver string) string {
	resolver = strings.TrimSpace(resolver)

	if resolver == "" {
		return resolver
	}

	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}

	if ip := net.ParseIP(resolver); ip != nil {
		return net.JoinHostPort(resolver, "53")
	}

	if strings.Count(resolver, ":") > 1 {
		return net.JoinHostPort(resolver, "53")
	}

	if strings.Contains(resolver, ":") {
		host, port, err := net.SplitHostPort(resolver)

		if err == nil && host != "" && port != "" {
			return resolver
		}
	}

	return net.JoinHostPort(resolver, "53")
}

func normalizeResolver(value string) string {
	return strings.TrimSpace(strings.Trim(value, "[]"))
}

func resolverHost(value string) string {
	value = normalizeResolver(value)

	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}

	return value
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)

		if value == "" {
			continue
		}

		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}

func typeName(recordType uint16) string {
	switch recordType {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypePTR:
		return "PTR"
	case dnsTypeMX:
		return "MX"
	case dnsTypeTXT:
		return "TXT"
	case dnsTypeAAAA:
		return "AAAA"
	default:
		return strconv.Itoa(int(recordType))
	}
}

func rcodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return strconv.Itoa(code)
	}
}

func formatDuration(value time.Duration) string {
	if value <= 0 {
		return "-"
	}

	if value < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(value)/float64(time.Microsecond))
	}

	return fmt.Sprintf("%.2fms", float64(value)/float64(time.Millisecond))
}

func formatHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var builder strings.Builder

	for i, value := range data {
		if i > 0 {
			builder.WriteByte(' ')
		}

		fmt.Fprintf(&builder, "%02x", value)
	}

	return builder.String()
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}

	return value
}

func truncate(value string, width int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.TrimSpace(value)

	runes := []rune(value)

	if len(runes) <= width {
		return value
	}

	if width <= 3 {
		return string(runes[:width])
	}

	return string(runes[:width-3]) + "..."
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dns-forensics: "+format+"\n", args...)
	os.Exit(1)
}
