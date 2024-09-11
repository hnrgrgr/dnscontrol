package diff2

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
)

// GlueChangeList is a list of GlueChange
type GlueChangeList []GlueChange

type GlueChange struct {
	Type Verb // Add, Change, Delete

	Key string   // Host
	Old []net.IP // Old glue IPs for the host
	New []net.IP // New glue IPs for the host
	Msg string   // Human-friendly explanation of what changed
}

func equalIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Slice(a, func(i, j int) bool {
		return bytes.Compare(a[i], a[j]) > 0
	})
	sort.Slice(b, func(i, j int) bool {
		return bytes.Compare(b[i], b[j]) > 0
	})
	for i, ip := range a {
		if !bytes.Equal(ip, b[i]) {
			return false
		}
	}
	return true
}

func GlueByRecord(existing models.GlueRecords, dc *models.DomainConfig) (GlueChangeList, error) {

	corrections := GlueChangeList{}
	_, desired := dc.Records.GroupedByFQDN()

	for _, d := range dc.Nameservers {

		// Ignore nameservers outside of our zone
		var host = d.Name
		if !strings.HasSuffix(host, dc.Name) {
			continue
		}

		// Collect desired IPs for the nameserver
		desiredIPs := desired[host].GetIPs()
		if len(desiredIPs) == 0 {
			// TODO GRGR warn or error ? NS without IP
			// Or is catched elsewhere ?
			continue
		}

		// Collect existing glue IPS for the nameserver
		existingIPs := existing.FindExistingGlue(host)

		// Create new glue IPs or update existing glue IPs
		if existingIPs == nil || len(existingIPs) == 0 {
			newIps := []string{}
			for _, ip := range desiredIPs {
				newIps = append(newIps, ip.String())
			}
			// TODO grgr improve msg
			msg := fmt.Sprintf("Add glue IPs for %s: -> %s",
				host,
				strings.Join(newIps, ", "))
			corrections = append(corrections, GlueChange{
				Type: CREATE,
				Key:  host,
				New:  desiredIPs,
				Msg:  msg,
			})
		} else if !equalIPs(desiredIPs, existingIPs) {
			oldIps := []string{}
			newIps := []string{}
			for _, ip := range existingIPs {
				oldIps = append(oldIps, ip.String())
			}
			for _, ip := range desiredIPs {
				newIps = append(newIps, ip.String())
			}
			// TODO grgr improve msg
			msg := fmt.Sprintf("Update glue IPs for %s: %s -> %s",
				host,
				strings.Join(oldIps, ", "),
				strings.Join(newIps, ", "))
			corrections = append(corrections, GlueChange{
				Type: CHANGE,
				Key:  host,
				Old:  existingIPs,
				New:  desiredIPs,
				Msg:  msg,
			})
		}
	}

	// Delete unrequired glue records

	for _, r := range existing {
		if !dc.IsANameserver(r.Host) {
			oldIps := []string{}
			for _, ip := range r.IPs {
				oldIps = append(oldIps, ip.String())
			}
			// TODO grgr improve msg
			msg := fmt.Sprintf("Remove glue IPs for %s: %s ->",
				r.Host,
				strings.Join(oldIps, ", "))
			corrections = append(corrections, GlueChange{
				Type: DELETE,
				Key:  r.Host,
				Old:  r.IPs,
				Msg:  msg,
			})
		}
	}

	return corrections, nil

}
