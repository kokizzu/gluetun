package surfshark

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Surfshark_filterServers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		servers   []models.SurfsharkServer
		selection configuration.ServerSelection
		filtered  []models.SurfsharkServer
		err       error
	}{
		"no server available": {
			selection: configuration.ServerSelection{
				VPN: constants.OpenVPN,
			},
			err: errors.New("no server found: for VPN openvpn; protocol udp"),
		},
		"no filter": {
			servers: []models.SurfsharkServer{
				{Hostname: "a", UDP: true},
				{Hostname: "b", UDP: true},
				{Hostname: "c", UDP: true},
			},
			filtered: []models.SurfsharkServer{
				{Hostname: "a", UDP: true},
				{Hostname: "b", UDP: true},
				{Hostname: "c", UDP: true},
			},
		},
		"filter OpenVPN out": {
			selection: configuration.ServerSelection{
				VPN: constants.Wireguard,
			},
			servers: []models.SurfsharkServer{
				{OpenVPN: true, UDP: true, Hostname: "a"},
				{OpenVPN: true, UDP: true, Wireguard: true, Hostname: "b"},
				{OpenVPN: true, UDP: true, Hostname: "c"},
			},
			filtered: []models.SurfsharkServer{
				{OpenVPN: true, UDP: true, Wireguard: true, Hostname: "b"},
			},
		},
		"filter by region": {
			selection: configuration.ServerSelection{
				Regions: []string{"b"},
			},
			servers: []models.SurfsharkServer{
				{Region: "a", UDP: true},
				{Region: "b", UDP: true},
				{Region: "c", UDP: true},
			},
			filtered: []models.SurfsharkServer{
				{Region: "b", UDP: true},
			},
		},
		"filter by country": {
			selection: configuration.ServerSelection{
				Countries: []string{"b"},
			},
			servers: []models.SurfsharkServer{
				{Country: "a", UDP: true},
				{Country: "b", UDP: true},
				{Country: "c", UDP: true},
			},
			filtered: []models.SurfsharkServer{
				{Country: "b", UDP: true},
			},
		},
		"filter by city": {
			selection: configuration.ServerSelection{
				Cities: []string{"b"},
			},
			servers: []models.SurfsharkServer{
				{City: "a", UDP: true},
				{City: "b", UDP: true},
				{City: "c", UDP: true},
			},
			filtered: []models.SurfsharkServer{
				{City: "b", UDP: true},
			},
		},
		"filter by hostname": {
			selection: configuration.ServerSelection{
				Hostnames: []string{"b"},
			},
			servers: []models.SurfsharkServer{
				{Hostname: "a", UDP: true},
				{Hostname: "b", UDP: true},
				{Hostname: "c", UDP: true},
			},
			filtered: []models.SurfsharkServer{
				{Hostname: "b", UDP: true},
			},
		},
		"filter by OpenVPN TCP": {
			selection: configuration.ServerSelection{
				VPN:     constants.OpenVPN,
				OpenVPN: configuration.OpenVPNSelection{TCP: true},
			},
			servers: []models.SurfsharkServer{
				{OpenVPN: true, Hostname: "a"},
				{OpenVPN: true, TCP: true, Hostname: "b"},
				{OpenVPN: true, Hostname: "c"},
			},
			filtered: []models.SurfsharkServer{
				{OpenVPN: true, TCP: true, Hostname: "b"},
			},
		},
		"filter by OpenVPN UDP": {
			selection: configuration.ServerSelection{
				VPN: constants.OpenVPN,
			},
			servers: []models.SurfsharkServer{
				{OpenVPN: true, Hostname: "a"},
				{OpenVPN: true, UDP: true, Hostname: "b"},
				{OpenVPN: true, Hostname: "c"},
			},
			filtered: []models.SurfsharkServer{
				{OpenVPN: true, UDP: true, Hostname: "b"},
			},
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			randSource := rand.NewSource(0)

			m := New(testCase.servers, randSource)

			servers, err := m.filterServers(testCase.selection)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.filtered, servers)
		})
	}
}
