package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Kubernetes resources the config layer reads:
//
//   - Secret of type kubernetes.io/tls: tls.crt, tls.key and ca.crt, as key
//     material (https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets);
//   - ingress-nginx ConfigMap keys ssl-ciphers and ssl-ecdh-curve
//     (https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/);
//   - Ingress annotation nginx.ingress.kubernetes.io/ssl-ciphers
//     (https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/);
//   - cert-manager Certificate spec.privateKey.algorithm and size. cert-manager
//     documents the size defaults (RSA 2048, ECDSA 256) but no default
//     algorithm, so a Certificate without one is not reported
//     (https://cert-manager.io/docs/reference/api-docs/).
const ingressCiphers = "nginx.ingress.kubernetes.io/ssl-ciphers"

// k8sItem is either a directive or key material found in a manifest.
type k8sItem struct {
	directive *directive
	material  []material
	notes     []string
}

func (s *Scanner) parseKubernetes(data []byte) []k8sItem {
	var out []k8sItem
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out // not YAML, or malformed: keep what was read
		}
		root := &doc
		if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
			root = root.Content[0]
		}
		if root.Kind != yaml.MappingNode {
			continue
		}
		kind := scalar(get(root, "kind"))
		if scalar(get(root, "apiVersion")) == "" || kind == "" {
			continue
		}
		name := scalar(get(get(root, "metadata"), "name"))
		ref := kind + "/" + name
		switch kind {
		case "Secret":
			out = append(out, s.tlsSecret(root, ref)...)
		case "ConfigMap":
			data := get(root, "data")
			for key, k := range map[string]valueKind{"ssl-ciphers": tlsCiphers, "ssl-ecdh-curve": tlsGroups} {
				if v := get(data, key); v != nil && scalar(v) != "" {
					out = append(out, k8sItem{directive: &directive{line: v.Line, symbol: "k8s:" + ref + ":" + key, kind: k, value: scalar(v),
						text: key + ": " + scalar(v)}})
				}
			}
		case "Ingress":
			if v := get(get(get(root, "metadata"), "annotations"), ingressCiphers); v != nil && scalar(v) != "" {
				out = append(out, k8sItem{directive: &directive{line: v.Line, symbol: "k8s:" + ref + ":" + ingressCiphers, kind: tlsCiphers,
					value: scalar(v), text: ingressCiphers + ": " + scalar(v)}})
			}
		case "Certificate":
			if !strings.HasPrefix(scalar(get(root, "apiVersion")), "cert-manager.io/") {
				continue
			}
			if m := s.certManagerKey(get(get(root, "spec"), "privateKey"), ref); m != nil {
				out = append(out, k8sItem{material: m})
			}
		}
	}
	return out
}

// tlsSecret reads the certificates and keys of a kubernetes.io/tls Secret.
// Values in data are base64; values in stringData are plain.
func (s *Scanner) tlsSecret(root *yaml.Node, ref string) []k8sItem {
	if scalar(get(root, "type")) != "kubernetes.io/tls" {
		return nil
	}
	var out []k8sItem
	for _, section := range []string{"data", "stringData"} {
		m := get(root, section)
		for _, key := range []string{"tls.crt", "tls.key", "ca.crt"} {
			v := get(m, key)
			if v == nil {
				continue
			}
			raw := []byte(scalar(v))
			if section == "data" {
				dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scalar(v)), ""))
				if err != nil {
					out = append(out, k8sItem{notes: []string{fmt.Sprintf("line %d: %s %s is not valid base64", v.Line, ref, key)}})
					continue
				}
				raw = dec
			}
			// Positions inside a decoded value don't map to file lines, so every
			// block is reported at the key's line.
			mats, notes := s.keyMaterial(raw, v.Line, true)
			for i := range mats {
				mats[i].line = v.Line
				mats[i].symbol = "k8s:" + ref + ":" + key + ":" + mats[i].symbol
			}
			out = append(out, k8sItem{material: mats, notes: notes})
		}
	}
	return out
}

func (s *Scanner) certManagerKey(pk *yaml.Node, ref string) []material {
	alg := scalar(get(pk, "algorithm"))
	if alg == "" {
		return nil
	}
	size := scalar(get(pk, "size"))
	line := get(pk, "algorithm").Line
	var family, params string
	switch alg {
	case "RSA":
		family, params = "RSA", size
		if params == "" {
			params = "2048"
		}
	case "ECDSA":
		family = "ECDSA"
		switch size {
		case "", "256":
			params = "P-256"
		case "384":
			params = "P-384"
		case "521":
			params = "P-521"
		default:
			return nil
		}
	case "Ed25519":
		family, params = "EdDSA", "Ed25519"
	default:
		return nil
	}
	a, err := familyAsset(s.db, family, model.PrimitiveSignature, params)
	if err != nil {
		return nil
	}
	ev := fmt.Sprintf("cert-manager %s private key: algorithm %s", ref, alg)
	if size != "" {
		ev += ", size " + size
	}
	return []material{{a, "k8s:" + ref + ":spec.privateKey", line, ev}}
}

// get returns a mapping node's value for key, or nil.
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
