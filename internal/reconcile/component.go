package reconcile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Component is one deployable unit: the files that build it and the
// endpoints that serve it.
type Component struct {
	Name  string   `yaml:"name"`
	Paths []string `yaml:"paths"` // path prefixes relative to the scan root; "." for all
	Hosts []string `yaml:"hosts"` // "host", "host:port", or "*" for all
}

// DefaultComponent holds every finding: one project and its endpoints.
var DefaultComponent = Component{Name: "default", Paths: []string{"."}, Hosts: []string{"*"}}

// ParseComponents reads a components file:
//
//	components:
//	  - name: web
//	    paths: [services/web]
//	    hosts: [web.example.org:443]
//
// A finding belongs to the first component that matches it.
func ParseComponents(r io.Reader) ([]Component, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc struct {
		Components []Component `yaml:"components"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("components: %w", err)
	}
	var errs []error
	names := map[string]bool{}
	for i, c := range doc.Components {
		if c.Name == "" || names[c.Name] {
			errs = append(errs, fmt.Errorf("component %d: missing or duplicate name %q", i+1, c.Name))
		}
		names[c.Name] = true
		if len(c.Paths)+len(c.Hosts) == 0 {
			errs = append(errs, fmt.Errorf("component %q: no paths or hosts", c.Name))
		}
	}
	if len(doc.Components) == 0 {
		errs = append(errs, errors.New("components: none defined"))
	}
	return doc.Components, errors.Join(errs...)
}

func (c Component) contains(f model.Finding) bool {
	if f.Location.Layer == model.LayerNetwork {
		host, _, err := net.SplitHostPort(f.Location.Path)
		if err != nil {
			host = f.Location.Path
		}
		for _, h := range c.Hosts {
			if h == "*" || strings.EqualFold(h, f.Location.Path) || strings.EqualFold(h, host) {
				return true
			}
		}
		return false
	}
	p := path.Clean(f.Location.Path)
	for _, prefix := range c.Paths {
		prefix = path.Clean(prefix)
		if prefix == "." || p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}
