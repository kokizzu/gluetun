package expressvpn

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool) (lines []string) {
	//nolint:gomnd
	providerSettings := utils.OpenVPNProviderSettings{
		RemoteCertTLS: true,
		AuthUserPass:  true,
		Ciphers: []string{
			openvpn.AES256gcm, openvpn.AES256cbc, openvpn.AES128gcm,
		},
		Auth:           openvpn.SHA512,
		CAs:            []string{"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"}, //nolint:lll
		Cert:           "MIIDTjCCAregAwIBAgIDKzZvMA0GCSqGSIb3DQEBCwUAMIGFMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFTATBgNVBAcTDFNhbkZyYW5jaXNjbzEVMBMGA1UEChMMRm9ydC1GdW5zdG9uMRgwFgYDVQQDEw9Gb3J0LUZ1bnN0b24gQ0ExITAfBgkqhkiG9w0BCQEWEm1lQG15aG9zdC5teWRvbWFpbjAgFw0xNjExMDMwMzA2MThaGA8yMDY2MTEwMzAzMDYxOFowgYoxCzAJBgNVBAYTAlZHMQwwCgYDVQQIDANCVkkxEzARBgNVBAoMCkV4cHJlc3NWUE4xEzARBgNVBAsMCkV4cHJlc3NWUE4xHDAaBgNVBAMME2V4cHJlc3N2cG5fY3VzdG9tZXIxJTAjBgkqhkiG9w0BCQEWFnN1cHBvcnRAZXhwcmVzc3Zwbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrOYt/KOi2uMDGev3pXg8j1SO4J/4EVWDF7vJcKr2jrZlqD/zuAFx2W1YWvwumPO6PKH4PU9621aNdiumaUkv/RplCfznnnxqobhJuTE2oA+rS1bOq+9OhHwF9jgNXNVk+XX4d0toST5uGE6Z3OdmPBur8o5AlCf78PDSAwpFOw5HrgLqOEU4hTweC1/czX2VsvsHv22HRI6JMZgP8gGQii/p9iukqfaJvGdPciL5p1QRBUQIi8P8pNvEp1pVIpxYj7/LOUqb2DxFvgmp2v1IQ0Yu88SWsFk84+xAYHzfkLyS31Sqj5uLRBnJqx3fIlOihQ50GI72fwPMwo+OippvVAgMBAAGjPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgSwMB0GA1UdDgQWBBSkBM1TCX9kBgFsv2RmOzudMXa9njANBgkqhkiG9w0BAQsFAAOBgQA+2e4b+33zFmA+1ZQ46kWkfiB+fEeDyMwMLeYYyDS2d8mZhNZKdOw7dy4Ifz9Vqzp4aKuQ6j61c6k1UaQQL0tskqWVzslSFvs9NZyUAJLLdGUc5TT2MiLwiXQwd4UvH6bGeePdhvB4+ZbW7VMD7TE8hZhjhAL4F6yAP1EQvg3LDA==",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       //nolint:lll
		RSAKey:         "MIIEpAIBAAKCAQEAqzmLfyjotrjAxnr96V4PI9UjuCf+BFVgxe7yXCq9o62Zag/87gBcdltWFr8Lpjzujyh+D1PettWjXYrpmlJL/0aZQn85558aqG4SbkxNqAPq0tWzqvvToR8BfY4DVzVZPl1+HdLaEk+bhhOmdznZjwbq/KOQJQn+/Dw0gMKRTsOR64C6jhFOIU8Hgtf3M19lbL7B79th0SOiTGYD/IBkIov6fYrpKn2ibxnT3Ii+adUEQVECIvD/KTbxKdaVSKcWI+/yzlKm9g8Rb4Jqdr9SENGLvPElrBZPOPsQGB835C8kt9Uqo+bi0QZyasd3yJTooUOdBiO9n8DzMKPjoqab1QIDAQABAoIBAHgsekC0SKi+AOcNOZqJ3pxqophE0V7fQX2KWGXhxZnUZMFxGTc936deMYzjZ1y0lUa6x8cgOUcfqHol3hDmw9oWBckLHGv5Wi9umdb6DOLoZO62+FQATSdfaJ9jheq2Ub2YxsRN0apaXzB6KDKz0oM0+sZ4Udn9Kw6DfuIELRIWwEx4w0v3gKW7YLC4Jkc4AwLkPK03xEA/qImfkCmaMPLhrgVQt+IFfP8bXzL7CCC04rNU/IS8pyjex+iUolnQZlbXntF7Bm4V2mz0827ZVqrgAb/hEQRlsTW3rRkVh+rrdoUE7BCZRTFmRCbLoShjN6XuSf4sAus8ch4UEN12gN0CgYEA4o/tSvij1iPaXLmt4KOEuxqmSGB8MLKhFde8lBbNdrDgxiIH9bH7khKx15XRTX0qLDbs8b2/UJygZG0Aa1kIBqZTXTgeMAuxPRTesALJPdqQ/ROnbJcdFkI7gllrAG8VB0fH4wTRsRd0vWEB6YlCdE107u6LEsLAHxOj9Q5819cCgYEAwXjx9RkQ2qITBx5Ewib8YsltA0n3cmRomPicLlsnKV5DfvyCLpFIsZ1h3f9dUpfxRLwzp8wcoLiq9cCoOGdu1udw/yBTqmhaXWhUK/g77f9Ze2ZB1OEhuyKLYJ1vW/h/Z/a1aPCMxZqsDTPCePsuO8Cez5gqs8LjM3W7EyzRxDMCgYEAvhHrDFt975fSiLoJgo0MPIAGAnBXn+8sLwv3m/FpW+rWF8LTFK/Fku12H5wDpNOdvswxijkauIE+GiJMGMLvdcyx4WHECaC1h73reJRNykOEIZ0Md5BrCZJ1JEzp9Mo8RQhWTEFtvfkkqgApP4g0pSeaMx0StaGG1kt+4IbP+68CgYBrZdQKlquAck/Vt7u7eyDHRcE5/ilaWtqlb/xizz7h++3D5C/v4b5UumTFcyg+3RGVclPKZcfOgDSGzzeSd/hTW46iUTOgeOUQzQVMkzPRXdoyYgVRQtgSpY5xR3O1vjAbahwx8LZ0SvQPMBhYSDbV/Isr+fBacWjl/AipEEwxeQKBgQDdrAEnVlOFoCLw4sUjsPoxkLjhTAgI7CYk5NNxX67Rnj0tp+Y49+sGUhl5sCGfMKkLShiON5P2oxZa+B0aPtQjsdnsFPa1uaZkK4c++SS6AetzYRpVDLmLp7/1CulE0z3O0sBekpwiuaqLJ9ZccC81g4+2j8j6c50rIAct3hxIxw==",                                                                                                                                                                                                                                                                                                                                                                                                                                                                               //nolint:lll
		TLSAuth:        "48d9999bd71095b10649c7cb471c1051b1afdece597cea06909b99303a18c67401597b12c04a787e98cdb619ee960d90a0165529dc650f3a5c6fbe77c91c137dcf55d863fcbe314df5f0b45dbe974d9bde33ef5b4803c3985531c6c23ca6906d6cd028efc8585d1b9e71003566bd7891b9cc9212bcba510109922eed87f5c8e66d8e59cbd82575261f02777372b2cd4ca5214c4a6513ff26dd568f574fd40d6cd450fc788160ff68434ce2bf6afb00e710a3198538f14c4d45d84ab42637872e778a6b35a124e700920879f1d003ba93dccdb953cdf32bea03f365760b0ed8002098d4ce20d045b45a83a8432cc737677aed27125592a7148d25c87fdbe0a3f6",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       //nolint:lll
		MssFix:         1200,
		FastIO:         true,
		Fragment:       1300,
		SndBuf:         524288,
		RcvBuf:         524288,
		KeyDirection:   "1",
		VerifyX509Type: "name-prefix",
		// Always verify against `Server` x509 name prefix, security hole I guess?
		VerifyX509Name: "Server",
	}
	return utils.OpenVPNConfig(providerSettings, connection, settings, ipv6Supported)
}
