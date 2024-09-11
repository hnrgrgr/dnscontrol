package models

import (
	"net"
)

type GlueRecord struct {
	Host string
	IPs  []net.IP
}

type GlueRecords []*GlueRecord

func (records GlueRecords) FindExistingGlue(host string) []net.IP {
	for _, r := range records {
		if r.Host == host {
			return r.IPs
		}
	}
	return nil
}
