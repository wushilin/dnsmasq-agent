# DNSMASQ Agent
This software is a DNS api that manipulates DNSMASQ host file.

DNSMASQ host file is a /etc/hosts like file that looks like this:
```
8.8.8.8 dns.google.com dns1.google.com
8.8.4.4 alt.dns.google.com
...
```

We are building a daemon to manipulate a SQLite file and periodically export to the target hosts file then 
trigger dnsmasq reload, up to once every x seconds.


# The config
```
target=/etc/dnsmasq.hosts
flush_interval_ms=5000
port=8000
bind=0.0.0.0
basic_auth=admin:password
dnsmasq_pid_file=/run/dnsmasq/dnsmasq.pid
db_file=./hosts.sqlite
```

# what it does
Since hosts file primary key is the IP, and there can be one or more hosts under it, we design it simple:

## Adding a host under specific IP
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace_mode":"both"}
```
It binds `10.2.2.2` to `test.com`. By default, `replace_mode` is `both`, so `10.2.2.2` only has this host and `test.com` only has this IP.

Replacement modes:
- `both`: replace other hosts under this IP and replace other IPs under this host
- `host`: replace other hosts under this IP, but allow this host to exist under multiple IPs
- `ip`: replace other IPs under this host, but allow this IP to have multiple hosts
- `none`: add this host/IP pair alongside existing entries

Example: make the IP point only to this host, while allowing the host to keep other IPs:
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace_mode":"host"}
```

Example: make the host point only to this IP, while allowing the IP to keep other hosts:
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace_mode":"ip"}
```

Legacy clients can still send `replace` and `replace_ip`; `replace_mode` is preferred for new clients.

This api essentially serviced as add, replace feature

Client can also optionally specify a TTL in seconds:
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace_mode":"none", "ttl":1800}
```

or
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace_mode":"none", "ttl_seconds":1800}
```

When a TTL is specified, the hostname is treated as ephemeral and disappears after the TTL expires unless the client refreshes it by calling `add_host` again. This is useful for systems like Docker watchers that continuously publish active entries but may not be able to delete stale ones. If the same `ip` + `host` is added again, the TTL and registration time are refreshed from the new API call.

# Delete an entry completely
```
DELETE /dnsmasq/10.2.2.2
```
Remove binding for 10.2.2.2
We should tell client if some entries is removed or not at all. response is always 200

```
{"removed_host_count":3}
```

# Delete an specific hostname
```
DELETE /dnsmasq/10.2.2.2/test.com
```
delete test.com from 10.2.2.2.
It is always OK to do so. but we can tell client whether if there is any entries actually removed.
e.g.
```
{"removed_host_count": 1}
```

# List all hosts
Get all hosts and IPs in config
```
GET /dnsmasq/all
```
Response:
```
{"10.2.2.2":[{"name":"test.com", "ttl_seconds":0, "registered_time":"2025-04-01T02:44:32.422+08"}, {"name": "test1.com", "ttl_seconds":1800, "registered_time":"2025-04-01T02:44:32.422+08"}]}
```

Note ttl_seconds 0 means no ttl (kept forever)

# Built-in UI
There is a built-in browser UI at:
```
GET /dnsmasq/ui/index.html
```

The following paths redirect to the UI:
```
GET /dnsmasq/
GET /dnsmasq/index.html
```

The UI reuses the same APIs described above and uses AJAX for operations such as:
- add / replace host
- list all hosts
- delete host
- delete IP
- force export now

The add form exposes `replace_mode` with `both`, `host`, `ip`, and `none`.

The UI should include CSRF protection for mutating requests. A CSRF token is issued with the UI page and sent back on browser-triggered write operations.

# Force export immediately
Trigger an immediate export from sqlite to the target hosts file.
```
POST /dnsmasq/export_now
```

This endpoint bypasses:
- the `db_generation == file_generation` skip check
- the byte-by-byte file diff gate

It simply forces the current sqlite-backed state to be rendered, written to the target file, and reloaded via `SIGHUP`.



# Implementation
The code is implemented using axum. All APIs are done in sqlite, and flush to file is every `flush_interval_ms`. The SQLITE is the source of truth. Once flushed, we should send a "HUP" signal to the PID specified. Note if external edits is done by someone else in the target file, they are overwritten brutely.

All APIs, flush attempt, and are to be clearly logged to stdout with info/debug etc levels.

Upon initial start, load all hosts from the sqlite. During flush, all APIs can still work, but they may not be guanrateed to be flushed now and may only be flushed next flush cycle.

All hosts are converted to lower case at API level, so they are compared case-insensitively.

The SQLITE table should use normalized `ip` + `lower(host)` as the unique primary key, together with the associated ttl and registration time.

There should also be a simple sqlite metadata table that stores:
- `db_generation`
- `file_generation`

`db_generation` is incremented whenever there is any effective change in sqlite, including:
- add host
- replace hosts under an IP
- delete by IP
- delete by host
- TTL expiry cleanup

`file_generation` records the latest generation that has already been checked/exported against the target file.

When `db_generation == file_generation`, there is no pending sqlite change to export.

This is not perfectly atomic with file export, but it is acceptable. In a race, we may mark `file_generation = x` while the rendered export already effectively reflects `x + 1` or `x + 2`. That is still safe, because the next flush cycle will check again, and the file-content comparison gate will prevent unnecessary replacement and SIGHUP.


The write out process should write the entries in a deterministic way. e.g. sort IP first, then within the IP, sort by hosts.

And we write the rendered content to `<target>.tmp` first, then compare that temporary file against the existing target file. If they are identical, we remove the temp file and skip rewriting the target to avoid spamming the server with `SIGHUP`. If they differ, we overwrite the target file directly, close it, remove the temp file, and then issue `SIGHUP`.

The `/dnsmasq/export_now` endpoint is a special case:
- it bypasses the generation check
- it bypasses the file diff check
- it always writes the current rendered state to the target file
- it always issues `SIGHUP`

# LXC registration helper
There is also a helper binary named `lxc_dns_register` for refreshing ephemeral DNS entries from LXC.

Example:
```
cargo run --bin lxc_dns_register -- \
  --lxc-path /path/to/lxc \
  --suffix titan \
  --mask 192.168.0.0/24 \
  --agent 192.168.33.22:8000 \
  --user admin:password
```

What it does:
- runs `lxc ls --format json`
- keeps only instances whose status is `Running`
- extracts IP addresses from the LXC state payload
- keeps only IPs inside the provided CIDR mask
- registers `<instance-name>.<suffix>` to each matching IP through `POST /dnsmasq/add_host`
- uses `replace_mode=both` by default so each IP maps only to the generated hostname and each generated hostname maps only to that IP
- `--replace-mode host` keeps each IP exclusive to the generated hostname, but allows the same hostname to remain on multiple IPs
- `--replace-mode ip` keeps each hostname exclusive to the current IP, but allows the IP to keep other hosts
- `--replace-mode none` adds entries alongside existing mappings
- always uses `ttl=180` seconds (3 minutes)

The `--agent` value accepts `host:port` or `http://host:port`.
