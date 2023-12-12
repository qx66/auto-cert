package step

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseNameservers(t *testing.T) {
	nsServers := []string{
		"8.8.8.8",
		"1.1.1.1",
	}
	
	resolvers := ParseNameservers(nsServers)
	fmt.Println("resolvers: ", resolvers)
}

func TestGetNameservers(t *testing.T) {
	ns := getNameservers("/etc/resolv.conf", []string{"8.8.8.8:53"})
	fmt.Println("ns: ", ns)
}

func TestCreateDNSMsg(t *testing.T) {
	fqdn := dns.Fqdn("www.baidu.com.")
	fmt.Println("fqdn: ", fqdn)
	m := createDNSMsg(fqdn, dns.TypeA, true)
	m, err := sendDNSQuery(m, "8.8.8.8:53")
	require.NoError(t, err, "TestCreateDNSMsg sendDNSQuery 失败")
	
	fmt.Println("Answer: ", m.Answer)
	
}

func TestUpdateDomainWithCName(t *testing.T) {
	m := createDNSMsg("www.startops.com.cn", dns.TypeCNAME, true)
	
	s := updateDomainWithCName(m, "www.baidu.com")
	fmt.Println("UpdateDomainWithCName", s)
}

func TestDNSRecord(t *testing.T) {
	
	fqdn := dns.Fqdn("_axasd.acxcx.startops.com.cn")
	
	m := &dns.Msg{}
	m.SetQuestion(fqdn, dns.TypeTXT)
	m.SetEdns0(4096, false)
	m.RecursionDesired = true
	
	m, err := sendDNSQuery(m, "8.8.8.8:53")
	require.NoError(t, err, "TestCreateDNSMsg sendDNSQuery 失败")
	
	for _, rr := range m.Answer {
		if cn, ok := rr.(*dns.TXT); ok {
			if cn.Hdr.Name == fqdn {
			
			}
		}
	}
}

func TestVerifyTxtRecord(t *testing.T) {
	err := VerifyTxtRecord("_axasd.acxcx.startops.com.cn", "22222222222222", []string{"223.5.5.5:53"})
	require.NoError(t, err, "验证Txt记录失败")
}
