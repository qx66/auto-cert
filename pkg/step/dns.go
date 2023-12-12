package step

import (
	"errors"
	"github.com/miekg/dns"
	"net"
	"time"
)

var defaultNameservers = []string{
	"google-public-dns-a.google.com:53",
	"google-public-dns-b.google.com:53",
}

const defaultResolvConf = "/etc/resolv.conf"

var recursiveNameservers = getNameservers(defaultResolvConf, defaultNameservers)

var dnsTimeout = 10 * time.Second

func ParseNameservers(servers []string) []string {
	var resolvers []string
	for _, resolver := range servers {
		// ensure all servers have a port number
		if _, _, err := net.SplitHostPort(resolver); err != nil {
			resolvers = append(resolvers, net.JoinHostPort(resolver, "53"))
		} else {
			resolvers = append(resolvers, resolver)
		}
	}
	return resolvers
}

// getNameservers attempts to get systems nameservers before falling back to the defaults.
func getNameservers(path string, defaults []string) []string {
	config, err := dns.ClientConfigFromFile(path)
	if err != nil || len(config.Servers) == 0 {
		return defaults
	}
	
	return ParseNameservers(config.Servers)
}

func createDNSMsg(fqdn string, rtype uint16, recursive bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)
	
	if !recursive {
		m.RecursionDesired = false
	}
	
	return m
}

func dnsQuery(fqdn string, rtype uint16, nameservers []string, recursive bool) (*dns.Msg, error) {
	m := createDNSMsg(fqdn, rtype, recursive)
	
	var in *dns.Msg
	var err error
	
	for _, ns := range nameservers {
		in, err = sendDNSQuery(m, ns)
		if err == nil && len(in.Answer) > 0 {
			break
		}
	}
	return in, err
}

func sendDNSQuery(m *dns.Msg, ns string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: dnsTimeout}
	in, _, err := udp.Exchange(m, ns)
	
	if in != nil && in.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: dnsTimeout}
		// If the TCP request succeeds, the err will reset to nil
		in, _, err = tcp.Exchange(m, ns)
	}
	
	return in, err
}

// Update FQDN with CNAME if any.
func updateDomainWithCName(r *dns.Msg, fqdn string) string {
	for _, rr := range r.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			if cn.Hdr.Name == fqdn {
				return cn.Target
			}
		}
	}
	
	return fqdn
}

func VerifyTxtRecord(fqdn, value string, ns []string) error {
	fqdn = dns.Fqdn(fqdn)
	m := createDNSMsg(fqdn, dns.TypeTXT, true)
	if len(ns) != 0 {
		mx, err := sendDNSQuery(m, ns[0])
		if err != nil {
			return err
		}
		m = mx
	}
	
	for _, rr := range m.Answer {
		if cn, ok := rr.(*dns.TXT); ok {
			if cn.Hdr.Name == fqdn && value == cn.Txt[0] {
				return nil
			}
		}
	}
	
	return errors.New("not match")
}
