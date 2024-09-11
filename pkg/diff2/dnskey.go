package diff2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
)

type DnskeyChangeList []DnskeyChange

type DnskeyChange struct {
	Type Verb // Add, Delete
	Key  models.Dnskey
	Msg  string // Human-friendly explanation of what changed
}

func justDnskeyMsgs(cl DnskeyChangeList) []string {
	var msgs []string
	for _, c := range cl {
		msgs = append(msgs, c.Msg)
	}
	return msgs
}

func (cl DnskeyChangeList) JustMsg() string {
	msgs := justDnskeyMsgs(cl)
	return strings.Join(msgs, "\n")
}

func getKind(ds models.Dnskey) string {
	switch ds.Flags {
	case 256:
		return "ZSK"
	case 257:
		return "KSK"
	default:
		return strconv.FormatInt(int64(ds.Flags), 10)
	}
}

func ByDnskey(existing models.Dnskeys, dc *models.DomainConfig) (DnskeyChangeList, models.Dnskeys) {

	corrections := DnskeyChangeList{}
	dnskeys := dc.CollectedDnskeys

	if dc.RegisterDNSKEY == models.RegisterCDNSKEY {
		for _, ds := range existing {
			if !models.ExistsDnskey(ds, dnskeys) {
				corrections = append(corrections, DnskeyChange{
					Type: DELETE,
					Key:  ds,
					Msg:  fmt.Sprintf("Remove DNSKEY %d (%s, %s)", ds.Tag, getKind(ds), dc.Name),
				})
			}
		}
		for _, ds := range dc.CollectedCDnskeys {
			corrections = append(corrections, DnskeyChange{
				Type: CREATE,
				Key:  ds,
				Msg:  fmt.Sprintf("Add DNSKEY %d (%s)", ds.Tag, getKind(ds)),
			})
		}
	} else {

		if dc.RegisterDNSKEY == models.RegisterDNSKEY_KSK {
			dnskeys = models.Dnskeys{}
			for _, key := range dc.CollectedDnskeys {
				if key.Flags == 257 {
					dnskeys = append(dnskeys, key)
				}
			}
		}

		for _, ds := range existing {
			if !models.ExistsDnskey(ds, dnskeys) {
				corrections = append(corrections, DnskeyChange{
					Type: DELETE,
					Key:  ds,
					Msg:  fmt.Sprintf("Remove DNSKEY %d (%s, %s)", ds.Tag, getKind(ds), dc.Name),
				})
			}
		}
		for _, ds := range dnskeys {
			if !models.ExistsDnskey(ds, existing) {
				corrections = append(corrections, DnskeyChange{
					Type: CREATE,
					Key:  ds,
					Msg:  fmt.Sprintf("Add DNSKEY %d (%s)", ds.Tag, getKind(ds)),
				})
			}
		}
	}
	return corrections, dnskeys
}
