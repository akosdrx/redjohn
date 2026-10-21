// CI-only builder: official pinned GHSA transformer and schema-2 DB APIs.
// It consumes exactly two content-pinned CC-BY-4.0 upstream advisories.
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "sort"

    "github.com/aquasecurity/trivy-db/pkg/db"
    "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
    "github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
    bolt "go.etcd.io/bbolt"
)

func build() error {
    if len(os.Args) != 3 { return fmt.Errorf("expected owned input and fresh output directories") }
    if err := db.Init(os.Args[2]); err != nil { return err }
    defer db.Close()
    if err := ghsa.NewVulnSrc().Update(os.Args[1]); err != nil { return err }
    dbc := db.Config{}
    client := vulnerability.New(dbc)
    var ids []string
    err := dbc.ForEachVulnerabilityID(func(tx *bolt.Tx, id string) error {
        details := client.GetDetails(id)
        if len(details) == 0 || client.IsRejected(details) { return fmt.Errorf("missing or rejected advisory %s", id) }
        if err := dbc.SaveAdvisoryDetails(tx, id); err != nil { return err }
        if err := dbc.PutVulnerability(tx, id, client.Normalize(id, details)); err != nil { return err }
        ids = append(ids, id)
        return nil
    })
    if err != nil { return err }
    sort.Strings(ids)
    if len(ids) != 2 || ids[0] != "CVE-2022-25883" || ids[1] != "CVE-2023-32681" { return fmt.Errorf("unexpected fixture advisory IDs: %v", ids) }
    return json.NewEncoder(os.Stdout).Encode(map[string]any{"advisories": ids, "schema": db.SchemaVersion, "controlled_fixture": true})
}

func main() { if err := build(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) } }
