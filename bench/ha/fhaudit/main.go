// fhaudit: firehose completeness audit for HA tests. Records every create
// seen on a node's subscribeRepos and writes it to -out on SIGINT/SIGTERM; the
// harness requires every acked create to appear (a stalled or gappy merge
// shows up as missing creates even when per-repo chains look clean). While it
// runs, <out>.seq holds the newest commit seq so far: the harness waits on it
// for a replay to reach the end.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/gorilla/websocket"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	host := flag.String("host", "http://127.0.0.1:7101", "PDS base URL")
	cursor := flag.String("cursor", "", "optional cursor")
	out := flag.String("out", "fhaudit.json", "output file")
	collection := flag.String("collection", "app.bsky.feed.post", "collection to record")
	flag.Parse()

	u := strings.Replace(strings.TrimRight(*host, "/"), "http", "ws", 1) + "/xrpc/com.atproto.sync.subscribeRepos"
	if *cursor != "" {
		u += "?cursor=" + *cursor
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(2)
	}
	conn.SetReadLimit(64 << 20)
	go func() { <-ctx.Done(); conn.Close() }()

	seen := map[string][]string{}
	type rec struct {
		Seq  int64  `json:"s"`
		Repo string `json:"d"`
		Rev  string `json:"r"`
	}
	var log []rec
	var events, reorders, dups, infos int64
	var infoNames []string
	var first, last int64 = -1, -1
	var lastTime string
	reason := "interrupted"
	prefix := *collection + "/"
	var newest atomic.Int64
	newest.Store(-1)
	go func() {
		written := int64(-2)
		for range time.Tick(100 * time.Millisecond) {
			if n := newest.Load(); n != written {
				tmp := *out + ".seq.tmp"
				if os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)), 0o644) == nil && os.Rename(tmp, *out+".seq") == nil {
					written = n
				}
			}
		}
	}()
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				reason = "connection: " + err.Error()
			}
			break
		}
		cr := cbg.NewCborReader(bytes.NewReader(msg))
		op, t, err := readHeader(cr)
		if err != nil || op != 1 {
			if op == -1 {
				reason = "error frame"
			}
			continue
		}
		if t == "#info" {
			infos++
			var i comatproto.SyncSubscribeRepos_Info
			if err := i.UnmarshalCBOR(cr); err == nil {
				infoNames = append(infoNames, i.Name)
			}
			continue
		}
		if t != "#commit" {
			continue
		}
		var c comatproto.SyncSubscribeRepos_Commit
		if err := c.UnmarshalCBOR(cr); err != nil {
			continue
		}
		events++
		if first < 0 {
			first = c.Seq
		}
		if c.Seq < last {
			reorders++
		} else if c.Seq == last {
			dups++
		}
		if c.Seq > last {
			last = c.Seq
			newest.Store(last)
		}
		lastTime = c.Time
		log = append(log, rec{c.Seq, c.Repo, c.Rev})
		for _, o := range c.Ops {
			if o.Action == "create" && strings.HasPrefix(o.Path, prefix) {
				seen[c.Repo] = append(seen[c.Repo], o.Path[len(prefix):])
			}
		}
	}
	b, _ := json.Marshal(map[string]any{
		"seen": seen, "commits": log, "events": events, "first_seq": first, "last_seq": last, "last_time": lastTime,
		"reorders": reorders, "dups": dups, "infos": infos, "info_names": infoNames, "end": reason, "at": time.Now().Format(time.RFC3339Nano),
	})
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("fhaudit:", events, "commits, last seq", strconv.FormatInt(last, 10), "end:", reason)
}

func readHeader(cr *cbg.CborReader) (int64, string, error) {
	maj, n, err := cr.ReadHeader()
	if err != nil {
		return 0, "", err
	}
	if maj != cbg.MajMap {
		return 0, "", fmt.Errorf("header not a map")
	}
	var op int64
	var t string
	for i := uint64(0); i < n; i++ {
		key, err := cbg.ReadString(cr)
		if err != nil {
			return 0, "", err
		}
		switch key {
		case "op":
			maj, v, err := cr.ReadHeader()
			if err != nil {
				return 0, "", err
			}
			if maj == cbg.MajNegativeInt {
				op = -1 - int64(v)
			} else {
				op = int64(v)
			}
		case "t":
			if t, err = cbg.ReadString(cr); err != nil {
				return 0, "", err
			}
		default:
			var d cbg.Deferred
			if err := d.UnmarshalCBOR(cr); err != nil {
				return 0, "", err
			}
		}
	}
	return op, t, nil
}
