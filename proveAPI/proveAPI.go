// Copyright 2017 Nick Johnson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proveAPI

import (
	"fmt"
	"strings"
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/arachnid/dnsprove/proofs"
	log "github.com/inconshreveable/log15"
	"github.com/miekg/dns"
)

type dnskeyEntry struct {
	name string
	algorithm uint8
	keytag uint16
}

type Client struct {
	c *dns.Client
	nameserver string
	knownHashes map[dnskeyEntry][]*dns.DS
	supportedAlgorithms map[uint8]struct{}
	supportedDigests map[uint8]struct{}
}

func (client *Client) addDS(ds *dns.DS) {
	key := dnskeyEntry{ds.Header().Name, ds.Algorithm, ds.KeyTag}
	client.knownHashes[key] = append(client.knownHashes[key], ds)
}

func (client *Client) supportsAlgorithm(algorithm uint8) bool {
	_, ok := client.supportedAlgorithms[algorithm]
	return ok
}

func (client *Client) supportsDigest(digest uint8) bool {
	_, ok := client.supportedDigests[digest]
	return ok
}

func NewClient(nameserver string, roots []*dns.DS, algorithms, digests map[uint8]struct{}) *Client {
	client := &Client{
		c: new(dns.Client),
		nameserver: nameserver,
		knownHashes: make(map[dnskeyEntry][]*dns.DS),
		supportedAlgorithms: algorithms,
		supportedDigests: digests,
	}
	for _, root := range roots {
		client.addDS(root)
	}
	return client
}

func (client *Client) Query(qtype uint16, qclass uint16, name string) (*dns.Msg, error) {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: []dns.Question{
			dns.Question{
				Name: dns.Fqdn(name),
				Qtype: qtype,
				Qclass: qclass,
			},
		},
	}

	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)
	m.Id = dns.Id()

	req, err := m.Pack()
	if err != nil {
		return nil, err
	}

	response, err := http.Post(client.nameserver, "application/dns-udpwireformat", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Got unexpected status from server: %s", response.Status)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var r dns.Msg
	err = r.Unpack(data)
	if err == nil {
		log.Debug("DNS response:\n" + r.String())
		log.Info("DNS query", "class", dns.ClassToString[qclass], "type", dns.TypeToString[qtype], "name", name, "answer", len(r.Answer), "extra", len(r.Extra), "ns", len(r.Ns))
	}
	return &r, err
}

func (client *Client) QueryWithProof(qtype, qclass uint16, name string) ([]proofs.SignedSet, bool, error) {
	found := false

	if name[len(name) - 1] != '.' {
		name = name + "."
	}

	r, err := client.Query(qtype, qclass, name)
	if err != nil {
		return nil, false, err
	}

	rrs := getRRset(r.Answer, name, qtype)
	var sigs []dns.RR
	if len(rrs) > 0 {
		found = true
		sigs = findSignatures(r.Answer, name)
		if len(sigs) == 0 {
			return nil, false, fmt.Errorf("No signed RRSETs available for %s %s", dns.TypeToString[qtype], name)
		}
	} else {
		rrs = getNSECRRs(r.Ns, name)
		if len(rrs) == 0 {
			return nil, false, fmt.Errorf("RR does not exist and no NSEC records returned for %s %s", dns.TypeToString[qtype], name)
		}
		log.Info("RR does not exist; got NSEC", "qtype", dns.TypeToString[qtype], "name", name)
		sigs = findSignatures(r.Ns, rrs[0].Header().Name)
		if len(sigs) == 0 {
			return nil, false, fmt.Errorf("RR does not exist and no signatures provided for NSEC records for %s %s", dns.TypeToString[qtype], name)
		}
	}

	for _, sig := range sigs {
		sig := sig.(*dns.RRSIG)
		if sig.TypeCovered != rrs[0].Header().Rrtype {
			continue
		}
		ret, err := client.verifyRRSet(sig, rrs)
		if err == nil {
			result := proofs.SignedSet{sig, rrs, name}
			ret = append(ret, result)
			return ret, found, nil
		}
		log.Warn("Failed to verify RRSET", "type", dns.TypeToString[rrs[0].Header().Rrtype], "name", name, "signername", sig.SignerName, "algorithm", dns.AlgorithmToString[sig.Algorithm], "keytag", sig.KeyTag, "err", err)
	}

	return nil, found, fmt.Errorf("Could not validate %s %s %s: no valid signatures found", dns.ClassToString[qclass], dns.TypeToString[qtype], name)
}

func (client *Client) verifyRRSet(sig *dns.RRSIG, rrs []dns.RR) ([]proofs.SignedSet, error) {
	if !client.supportsAlgorithm(sig.Algorithm) {
		return nil, fmt.Errorf("Unsupported algorithm: %s", dns.AlgorithmToString[sig.Algorithm])
	}

	var sets []proofs.SignedSet
	var keys []dns.RR
	var err error
	if sig.Header().Name == sig.SignerName && rrs[0].Header().Rrtype == dns.TypeDNSKEY {
		// RRSet is self-signed; verify against itself
		keys = rrs
	} else {
		// Find the keys that signed this RRSET
		var found bool
		sets, found, err = client.QueryWithProof(dns.TypeDNSKEY, sig.Header().Class, sig.SignerName)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("DNSKEY %s not found", sig.SignerName)
		}
		keys = sets[len(sets)-1].Rrs
	}

	// Iterate over the keys looking for one that validly signs our RRSET
	for _, key := range keys {
		key := key.(*dns.DNSKEY)
		if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag || key.Header().Name != sig.SignerName {
			continue
		}
		if err := sig.Verify(key, rrs); err != nil {
			log.Error("Could not verify signature", "type", dns.TypeToString[rrs[0].Header().Rrtype], "signame", sig.Header().Name, "keyname", key.Header().Name, "algorithm", dns.AlgorithmToString[key.Algorithm], "keytag", key.KeyTag(), "key", key, "rrs", rrs, "sig", sig, "err", err)
			continue
		}
		if sig.Header().Name == sig.SignerName && rrs[0].Header().Rrtype == dns.TypeDNSKEY {
			// RRSet is self-signed; look for DS records in parent zones to verify
			sets, err = client.verifyWithDS(key)
			if err != nil {
				return nil, err
			}
		}
		return sets, nil
	}
	return nil, fmt.Errorf("Could not validate signature for %s %s %s (%s/%d); no valid keys found", dns.ClassToString[sig.Header().Class], dns.TypeToString[sig.Header().Rrtype], sig.Header().Name, dns.AlgorithmToString[sig.Algorithm], sig.KeyTag)
}

func (client *Client) verifyWithDS(key *dns.DNSKEY) ([]proofs.SignedSet, error) {
	keytag := key.KeyTag()
	// Check the roots
	for _, ds := range client.knownHashes[dnskeyEntry{key.Header().Name, key.Algorithm, keytag}] {
		if !client.supportsDigest(ds.DigestType) {
			continue
		}
		if strings.ToLower(key.ToDS(ds.DigestType).Digest) == strings.ToLower(ds.Digest) {
			return []proofs.SignedSet{}, nil
		}
	}

	// Look up the DS record
	sets, found, err := client.QueryWithProof(dns.TypeDS, key.Header().Class, key.Header().Name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("DS %s not found", key.Header().Name)
	}
	for _, ds := range sets[len(sets) - 1].Rrs {
		ds := ds.(*dns.DS)
		if !client.supportsDigest(ds.DigestType) {
			continue
		}
		if strings.ToLower(key.ToDS(ds.DigestType).Digest) == strings.ToLower(ds.Digest) {
			return sets, nil
		}
	}
	return nil, fmt.Errorf("Could not find any DS records that validate %s DNSKEY %s (%s/%d)", dns.ClassToString[key.Header().Class], key.Header().Name, dns.AlgorithmToString[key.Algorithm], keytag)
}

func filterRRs(rrs []dns.RR, qtype uint16) []dns.RR {
	ret := make([]dns.RR, 0)
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			ret = append(ret, rr)
		}
	}
	return ret
}

func findSignatures(rrs []dns.RR, name string) []dns.RR {
	ret := make([]dns.RR, 0)
	for _, rr := range rrs {
		// TODO: Wildcard support
		if rr.Header().Rrtype == dns.TypeRRSIG && rr.Header().Name == name {
			ret = append(ret, rr)
		}
	}
	return ret
}

func getRRset(rrs []dns.RR, name string, qtype uint16) []dns.RR {
	var ret []dns.RR
	for _, rr := range rrs {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == qtype {
			ret = append(ret, rr)
		}
	}
	return ret
}

func getNSECRRs(rrs []dns.RR, name string) []dns.RR {
	ret := make([]dns.RR, 0)
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok && nsecCovers(rr.Header().Name, name, nsec.NextDomain) {
			ret = append(ret, rr)
		}
	}
	return ret
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func compareDomainNames(a, b string) int {
	alabels := dns.SplitDomainName(a)
	blabels := dns.SplitDomainName(b)

	for i := 1; i <= min(len(alabels), len(blabels)); i++ {
		result := strings.Compare(alabels[len(alabels) - i], blabels[len(blabels) - i])
		if result != 0 {
			return result
		}
	}

	return len(alabels) - len(blabels)
}

func nsecCovers(owner, test, next string) bool {
	owner = strings.ToLower(owner)
	test = strings.ToLower(test)
	next = strings.ToLower(next)
	return compareDomainNames(owner, test) <= 0 && (compareDomainNames(test, next) <= 0 || strings.HasSuffix(test, next))
}
