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
tmp_dir=./tmp
```

# what it does
Since hosts file primary key is the IP, and there can be one or more hosts under it, we design it simple:

## Adding a host under specific IP
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace":false}
```
It bind 10.2.2.2 to test.com. If there is already a binding to 10.2.2.2, it added to the binding list (when replace is false)
if replace = true, all existing host name under 10.2.2.2 is removed, only this `test.com` is retained.

This api essentially serviced as add, replace feature

Client can also optionally specify a TTL in seconds:
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace":false, "ttl":1800}
```

or
```
POST /dnsmasq/add_host
{"ip": "10.2.2.2", "host":"test.com", "replace":false, "ttl_seconds":1800}
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

And we write to a separate file in tmp directory first, then compare if the written file is actually the same as existing file. The comparison is byte-by-byte on the deterministically rendered output. If they are identical, we do not replace it to avoid spamming the server with SIGHUP. We only issue sighup if a replace is really happened.

The `/dnsmasq/export_now` endpoint is a special case:
- it bypasses the generation check
- it bypasses the file diff check
- it always writes the current rendered state to the target file
- it always issues `SIGHUP`
