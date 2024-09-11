package models

import (
	//	"net"

	"github.com/miekg/dns"
)

type Dnskey struct {
	Tag   uint16
	Flags uint16
	// Protocol  uint8 // SHOULD be 3
	Algorithm uint8
	PublicKey string      `dns:"base64"`
	Original  interface{} // Store pointer to provider-specific record object.
}

type Dnskeys []Dnskey

// TODO grgr
func (orig Records) FilterDnskeys() (dest Records, keys, ckeys Dnskeys) {
	for _, r := range orig {
		switch r.Type {
		case "CDS":
		case "CDNSKEY":
			ckeys = append(ckeys, (Dnskey{
				Tag:       (r.ToRR()).(*dns.CDNSKEY).KeyTag(),
				Flags:     r.DnskeyFlags,
				Algorithm: r.DnskeyAlgorithm,
				PublicKey: r.DnskeyPublicKey,
				Original:  r}))
		case "DS":
		case "DNSKEY":
			keys = append(keys, (Dnskey{
				Tag:       (r.ToRR()).(*dns.DNSKEY).KeyTag(),
				Flags:     r.DnskeyFlags,
				Algorithm: r.DnskeyAlgorithm,
				PublicKey: r.DnskeyPublicKey,
				Original:  r}))
		default:
			dest = append(dest, r)
		}
	}
	return
}

func ExistsDnskey(ds Dnskey, set Dnskeys) bool {
	for _, key := range set {
		if key.Tag == ds.Tag {
			return true
		}
	}
	return false
}

// key.Flags != ds.Flags
// key.Algorithm != ds.Algorithm
// key.PublicKey != ds.PublicKey
