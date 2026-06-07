package openvpn

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestVerifyX509Name(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Server-12345",
			Country:    []string{"US"},
		},
	}

	// name-prefix matching
	if err := verifyX509Name(cert, "Server name-prefix"); err != nil {
		t.Errorf("expected no error for name-prefix match, got: %v", err)
	}
	if err := verifyX509Name(cert, "Client name-prefix"); err == nil {
		t.Error("expected error for mismatching name-prefix")
	}

	// name exact matching
	if err := verifyX509Name(cert, "Server-12345 name"); err != nil {
		t.Errorf("expected no error for name match, got: %v", err)
	}
	if err := verifyX509Name(cert, "Server name"); err == nil {
		t.Error("expected error for partial CN match under 'name' matchType")
	}

	// subject (DN) matching
	if err := verifyX509Name(cert, "Server-12345 subject"); err != nil {
		t.Errorf("expected no error for subject match, got: %v", err)
	}
	if err := verifyX509Name(cert, "US subject"); err != nil {
		t.Errorf("expected no error for subject country match, got: %v", err)
	}
	if err := verifyX509Name(cert, "UK subject"); err == nil {
		t.Error("expected error for mismatching subject country")
	}
}

func TestVerifyNSCertType(t *testing.T) {
	// 1. Certificate without extension
	certNoExt := &x509.Certificate{}
	if err := verifyNSCertType(certNoExt, "server"); err == nil {
		t.Error("expected error when NSCertType is required but extension is missing")
	}

	// 2. Certificate with extension (server bit set)
	netscapeCertTypeOID := asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	serverBitString := asn1.BitString{Bytes: []byte{0x40}, BitLength: 8}
	derValue, err := asn1.Marshal(serverBitString)
	if err != nil {
		t.Fatalf("failed to marshal bitstring: %v", err)
	}

	certServer := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    netscapeCertTypeOID,
				Value: derValue,
			},
		},
	}

	if err := verifyNSCertType(certServer, "server"); err != nil {
		t.Errorf("expected no error for server certificate, got: %v", err)
	}
	if err := verifyNSCertType(certServer, "client"); err == nil {
		t.Error("expected error for client check on server certificate")
	}

	// 3. Certificate with extension (client bit set)
	clientBitString := asn1.BitString{Bytes: []byte{0x80}, BitLength: 8}
	derValueClient, _ := asn1.Marshal(clientBitString)
	certClient := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    netscapeCertTypeOID,
				Value: derValueClient,
			},
		},
	}

	if err := verifyNSCertType(certClient, "client"); err != nil {
		t.Errorf("expected no error for client certificate, got: %v", err)
	}
	if err := verifyNSCertType(certClient, "server"); err == nil {
		t.Error("expected error for server check on client certificate")
	}
}
