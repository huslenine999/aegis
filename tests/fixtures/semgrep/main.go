package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func lookup(ctx context.Context, db *sql.DB, name string) {
	// ruleid: go-sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// ruleid: go-sql-injection
	db.ExecContext(ctx, "DELETE FROM users WHERE name = '"+name+"'")
	// ok: go-sql-injection
	db.Query("SELECT * FROM users WHERE name = $1", name)
}

func run(ctx context.Context, host string) {
	// ruleid: go-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ok: go-command-injection
	exec.Command("ping", "-c", "1", host).Run()
	// ok: go-command-injection
	exec.CommandContext(ctx, "sh", "-c", "uptime").Run()
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go-tainted-request
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	// ok: go-tainted-request
	safe, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))
	// ruleid: go-tainted-request
	http.Get(r.FormValue("url"))
	// ruleid: go-tainted-request
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
	w.Write(append(data, safe...))
}

func client() *http.Client {
	// ruleid: go-tls-insecure-skip-verify
	config := &tls.Config{InsecureSkipVerify: true}
	// ok: go-tls-insecure-skip-verify
	_ = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}

func page(comment string) template.HTML {
	// ok: go-unescaped-template
	_ = template.HTML("<b>static</b>")
	// ruleid: go-unescaped-template
	return template.HTML(comment)
}

func digest(data []byte) {
	// ruleid: go-weak-hash
	md5.Sum(data)
	// ok: go-weak-hash
	sha256.Sum256(data)
}

func main() {}
