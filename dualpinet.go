// Command dualpinet keeps a single IPv4 address available across a wired and
// a wireless interface on the same LAN, moving it to whichever currently
// reaches the upstream router.
//
// The router is discovered dynamically via IPv6 Router Advertisements
// (nothing about the router is hardcoded except its IPv4 address, which is
// the one piece of v4 state RAs don't carry). Health checks are ICMPv6
// pings to the router's link-local address, but only on the wired interface,
// so the wifi radio isn't burning air time when it isn't carrying traffic.
//
// Usage:
//
//	dualpinet --ip 10.0.0.32/16
//	dualpinet --ip 10.0.0.32/16 --router 10.0.0.1
//
// The first form derives the router as the .1 host of --ip's network.
package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	flagIP     = flag.String("ip", "", "floating IPv4 address with CIDR mask, e.g. 10.0.0.32/16")
	flagRouter = flag.String("router", "", "upstream router IPv4 (default: .1 of --ip's network)")
)

const (
	probeInterval       = 2 * time.Second
	probeTimeout        = 1 * time.Second
	failsBeforeFailover = 3 // ~6s of dead primary before flipping to secondary
	goodsBeforeFailback = 5 // ~10s of live primary before flipping back
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --ip <CIDR> [--router <IP>]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	ip, router, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}

	primary, secondary, err := pickInterfaces()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting: ip=%s router=%s primary=%s secondary=%s",
		ip, router, primary.Name, secondary.Name)

	for _, ifi := range []*net.Interface{primary, secondary} {
		if err := bringUp(ifi.Name); err != nil {
			log.Printf("warning: bring up %s: %v", ifi.Name, err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	run(ctx, ip, router, primary, secondary)
}

func parseFlags() (selfIP netip.Prefix, gw netip.Addr, err error) {
	if *flagIP == "" {
		return netip.Prefix{}, netip.Addr{}, errors.New("--ip is required")
	}
	p, err := netip.ParsePrefix(*flagIP)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("--ip: %w", err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, errors.New("--ip must be an IPv4 prefix")
	}
	var router netip.Addr
	if *flagRouter != "" {
		router, err = netip.ParseAddr(*flagRouter)
		if err != nil {
			return netip.Prefix{}, netip.Addr{}, fmt.Errorf("--router: %w", err)
		}
		if !router.Is4() {
			return netip.Prefix{}, netip.Addr{}, errors.New("--router must be IPv4")
		}
	} else {
		bs := p.Masked().Addr().As4()
		bs[3] = 1
		router = netip.AddrFrom4(bs)
	}
	return p, router, nil
}

// pickInterfaces returns the first wired ethernet (primary) and first
// wireless (secondary) interface found.
func pickInterfaces() (primary, secondary *net.Interface, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		ifi := &ifaces[i]
		if ifi.Flags&net.FlagLoopback != 0 || isVirtual(ifi.Name) {
			continue
		}
		switch {
		case isWireless(ifi.Name):
			if secondary == nil {
				secondary = ifi
			}
		case len(ifi.HardwareAddr) == 6:
			if primary == nil {
				primary = ifi
			}
		}
	}
	if primary == nil {
		return nil, nil, errors.New("no wired ethernet interface found")
	}
	if secondary == nil {
		return nil, nil, errors.New("no wireless interface found")
	}
	return primary, secondary, nil
}

func isWireless(name string) bool {
	for _, sub := range []string{"phy80211", "wireless"} {
		if _, err := os.Stat(filepath.Join("/sys/class/net", name, sub)); err == nil {
			return true
		}
	}
	return false
}

var virtualPrefixes = []string{
	"tailscale", "docker", "veth", "br-", "wg", "tun", "tap", "vboxnet",
}

func isVirtual(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

type controller struct {
	ip        netip.Prefix
	router    netip.Addr
	primary   *net.Interface
	secondary *net.Interface

	current    string // interface name currently holding ip, or "" if unassigned
	goodStreak int
	badStreak  int
}

func run(ctx context.Context, ip netip.Prefix, router netip.Addr, primary, secondary *net.Interface) {
	c := &controller{ip: ip, router: router, primary: primary, secondary: secondary}
	c.current = c.detectExisting()
	if c.current != "" {
		log.Printf("found %s already on %s; adopting", ip, c.current)
	}
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	c.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

// detectExisting returns the name of whichever managed interface currently
// holds the floating address, so a restarted daemon doesn't immediately
// flap it.
func (c *controller) detectExisting() string {
	want := c.ip.Addr()
	for _, ifi := range []*net.Interface{c.primary, c.secondary} {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				if netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}) == want {
					return ifi.Name
				}
			}
		}
	}
	return ""
}

func (c *controller) tick(ctx context.Context) {
	state, detail := c.probePrimary(ctx)

	switch state {
	case probeWaiting:
		// No RA on the primary yet. Don't flap to secondary on that alone
		// but if the link is *down*, probePrimary returns probeDead instead.
		if c.current == "" {
			log.Printf("waiting for RA on %s ...", c.primary.Name)
		}
		return
	case probeAlive:
		c.goodStreak++
		c.badStreak = 0
	case probeDead:
		c.badStreak++
		c.goodStreak = 0
	}

	want := c.current
	switch {
	case c.current == "" && state == probeAlive:
		want = c.primary.Name
	case c.current == "" && c.badStreak >= failsBeforeFailover:
		want = c.secondary.Name
	case c.current == c.primary.Name && c.badStreak >= failsBeforeFailover:
		want = c.secondary.Name
	case c.current == c.secondary.Name && c.goodStreak >= goodsBeforeFailback:
		want = c.primary.Name
	}
	if want == c.current {
		return
	}

	reason := detail
	if state == probeDead {
		reason = fmt.Sprintf("primary down [%d/%d]: %s", c.badStreak, failsBeforeFailover, detail)
	}
	log.Printf("switching %s -> %s (%s)", cmp.Or(c.current, "none"), want, reason)
	if err := c.apply(want); err != nil {
		log.Printf("apply: %v", err)
		return
	}
	c.current = want
}

type probeState int

const (
	probeWaiting probeState = iota // link up, no RA yet — verdict deferred
	probeAlive
	probeDead
)

// probePrimary returns the current health of the primary interface.
// detail is a short human string for logs.
func (c *controller) probePrimary(ctx context.Context) (probeState, string) {
	up, err := hasCarrier(c.primary.Name)
	if err != nil {
		return probeDead, "carrier read: " + err.Error()
	}
	if !up {
		return probeDead, "no carrier"
	}
	routerLL, err := upstreamRouterV6(c.primary.Name)
	if err != nil {
		return probeDead, "route read: " + err.Error()
	}
	if routerLL == "" {
		return probeWaiting, "no RA yet"
	}
	if err := ping6(ctx, c.primary.Name, routerLL); err != nil {
		return probeDead, "no reply from " + routerLL
	}
	return probeAlive, "router " + routerLL
}

func (c *controller) apply(iface string) error {
	// Remove from both interfaces first (idempotent — error on absent is
	// treated as success). Avoids the kernel briefly holding the address
	// on two interfaces, which would confuse ARP and rp_filter.
	for _, ifi := range []*net.Interface{c.primary, c.secondary} {
		runIPCmd("addr", "del", c.ip.String(), "dev", ifi.Name)
	}
	if err := runIPCmd("addr", "add", c.ip.String(), "dev", iface); err != nil {
		return fmt.Errorf("addr add: %w", err)
	}
	if err := runIPCmd("route", "replace", "default", "via", c.router.String(), "dev", iface); err != nil {
		return fmt.Errorf("route replace: %w", err)
	}
	return nil
}

// upstreamRouterV6 returns the link-local IPv6 of the default router seen
// on iface, as learned from received Router Advertisements. Returns "" if
// no RA has been received (or the route has expired).
func upstreamRouterV6(iface string) (string, error) {
	out, err := exec.Command("ip", "-6", "route", "show", "default", "dev", iface).Output()
	if err != nil {
		return "", err
	}
	// "default via fe80::xxx proto ra metric 1024 expires Nsec hoplimit 64 pref medium"
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, w := range fields {
			if w == "via" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", nil
}

func ping6(ctx context.Context, iface, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout+500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-6",
		"-c", "1",
		"-W", fmt.Sprintf("%d", int(probeTimeout.Seconds())),
		"-I", iface,
		addr)
	return cmd.Run()
}

func bringUp(iface string) error {
	return exec.Command("ip", "link", "set", iface, "up").Run()
}

func hasCarrier(iface string) (bool, error) {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "carrier"))
	if err != nil {
		// Reading carrier on an admin-down interface returns EINVAL. Treat
		// that as "no carrier" rather than a fatal error.
		if errors.Is(err, syscall.EINVAL) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

// runIPCmd runs `ip <args>` and treats the well-known idempotency errors
// ("File exists" on add, "Cannot find" on del) as success.
func runIPCmd(args ...string) error {
	cmd := exec.Command("ip", args...)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return nil
	}
	msg := stderr.String()
	if strings.Contains(msg, "File exists") ||
		strings.Contains(msg, "Cannot find") ||
		strings.Contains(msg, "does not exist") {
		return nil
	}
	return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(msg))
}
