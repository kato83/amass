// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrNameDoesNotExist     = errors.New("name does not exist")
	ErrNoRecordOfThisType   = errors.New("no record of this type")
	ErrFailedMaxDNSAttempts = errors.New("failed the maximum number of DNS attempts")
)

type baseline struct {
	address string
	qps     int
}

// baselineResolvers is a list of trusted public DNS resolvers.
var baselineResolvers = []baseline{
	{"8.8.8.8", 5},        // Google
	{"1.1.1.1", 5},        // Cloudflare
	{"9.9.9.9", 5},        // Quad9
	{"208.67.222.222", 5}, // Cisco OpenDNS
	{"84.200.69.80", 5},   // DNS.WATCH
	{"64.6.64.6", 5},      // Neustar DNS
	{"8.26.56.26", 5},     // Comodo Secure DNS
	{"205.171.3.65", 5},   // Level3
	{"134.195.4.2", 5},    // OpenNIC
	{"185.228.168.9", 5},  // CleanBrowsing
	{"76.76.19.19", 5},    // Alternate DNS
	{"37.235.1.177", 5},   // FreeDNS
	{"77.88.8.1", 5},      // Yandex.DNS
	{"94.140.14.140", 5},  // AdGuard
	{"38.132.106.139", 5}, // CyberGhost
	{"74.82.42.42", 5},    // Hurricane Electric
	{"76.76.2.0", 5},      // ControlD
}

var trusted *pool.Pool
var detector *wildcards.Detector

func PerformQuery(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	const (
		maxAttempts    = 50
		initialBackoff = 250 * time.Millisecond
		maxBackoff     = 4 * time.Second
		maxServfails   = 3
	)

	var servfails int
	for i := 1; i <= maxAttempts; i++ {
		msg := utils.QueryMsg(name, qtype)
		if qtype == dns.TypePTR {
			msg = utils.ReverseMsg(name)
		}

		if resp, err := dnsQuery(ctx, msg, trusted); err == nil && resp != nil {
			if wildcardDetected(ctx, resp, detector) {
				return nil, errors.New("wildcard detected")
			}
			if len(resp.Answer) > 0 {
				if rr := utils.AnswersByType(resp, qtype); len(rr) > 0 {
					var resolved []string
					for _, r := range rr {
						resolved = append(resolved, r.String())
					}
					return rr, nil
				}
			} else {
			}
		} else if err == ErrNameDoesNotExist {
			return nil, err
		} else if err == ErrNoRecordOfThisType {
			return nil, err
		} else if resp != nil && resp.Rcode == dns.RcodeServerFailure {
			servfails++
			if servfails >= maxServfails {
				return nil, ErrFailedMaxDNSAttempts
			}
		}

		// Exponential backoff capped at maxBackoff
		backoff := initialBackoff * (1 << min(i-1, 14))
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, ErrFailedMaxDNSAttempts
}

func wildcardDetected(ctx context.Context, resp *dns.Msg, r *wildcards.Detector) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(ctx, resp, dom)
	}
	return false
}

func dnsQuery(ctx context.Context, msg *dns.Msg, r *pool.Pool) (*dns.Msg, error) {
	if resp, err := r.Exchange(ctx, msg); err != nil {
		return nil, err
	} else if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNameDoesNotExist
	} else if resp.Rcode == dns.RcodeSuccess {
		if len(resp.Answer) == 0 {
			return nil, ErrNoRecordOfThisType
		}
		return resp, nil
	}
	return nil, errors.New("unexpected response")
}

func trustedResolvers() *pool.Pool {
	timeout := 3 * time.Second
	cpus := runtime.NumCPU()
	// wildcard detector
	serv := servers.NewNameserver("8.8.4.4")
	wconns := conn.New(cpus, selectors.NewSingle(timeout, serv))
	detector = wildcards.NewDetector(serv, wconns, nil)
	// the server pool
	var servs []types.Nameserver
	for _, r := range baselineResolvers {
		servs = append(servs, servers.NewNameserver(r.address))
	}
	sel := selectors.NewRoundRobin(timeout, servs...)
	//sel := selectors.NewAuthoritative(timeout, servers.NewNameserver)
	conns := conn.New(cpus, sel)
	return pool.New(0, sel, conns, nil)
}
