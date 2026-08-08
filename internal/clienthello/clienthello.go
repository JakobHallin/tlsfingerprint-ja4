// Package clienthello defines the TLS ClientHello information used to calculate
// a JA4 fingerprint.
package clienthello

// ClientHello contains the ordered ClientHello fields needed by JA4.
//
// Values are stored as they appeared on the wire. Filtering GREASE values,
// sorting values, and selecting the effective TLS version belong to the JA4
// calculation rather than this data model.
type ClientHello struct {
	LegacyVersion       uint16
	SupportedVersions   []uint16
	CipherSuites        []uint16
	ExtensionIDs        []uint16
	ServerNamePresent   bool
	ALPNProtocols       []string
	SignatureAlgorithms []uint16
}
