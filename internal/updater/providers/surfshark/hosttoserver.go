package surfshark

import (
	"net"

	"github.com/qdm12/gluetun/internal/models"
)

type hostToServer map[string]models.SurfsharkServer

func (hts hostToServer) add(host, region, country, city, retroLoc,
	pubKey string, tcp, udp bool) {
	server, ok := hts[host]
	if !ok {
		server.OpenVPN = true
		server.Hostname = host
		server.Region = region
		server.Country = country
		server.City = city
		server.RetroLoc = retroLoc
	}

	if pubKey != "" {
		server.Wireguard = true
		server.WgPubKey = pubKey
	}

	if tcp {
		server.TCP = tcp
	}
	if udp {
		server.UDP = udp
	}
	hts[host] = server
}

func (hts hostToServer) toHostsSlice() (hosts []string) {
	hosts = make([]string, 0, len(hts))
	for host := range hts {
		hosts = append(hosts, host)
	}
	return hosts
}

func (hts hostToServer) adaptWithIPs(hostToIPs map[string][]net.IP) {
	for host, IPs := range hostToIPs {
		server := hts[host]
		server.IPs = IPs
		hts[host] = server
	}
	for host, server := range hts {
		if len(server.IPs) == 0 {
			delete(hts, host)
		}
	}
}

func (hts hostToServer) toServersSlice() (servers []models.SurfsharkServer) {
	servers = make([]models.SurfsharkServer, 0, len(hts))
	for _, server := range hts {
		servers = append(servers, server)
	}
	return servers
}
