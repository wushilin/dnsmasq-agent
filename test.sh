#!/usr/bin/env bash

# Copy and run any of these one-liners directly.

curl -sS -u admin:password -H 'Content-Type: application/json' -X POST http://127.0.0.1:8000/dnsmasq/add_host --data-binary '{"ip":"10.2.2.2","host":"test.com","replace":false}'

curl -sS -u admin:password -H 'Content-Type: application/json' -X POST http://127.0.0.1:8000/dnsmasq/add_host --data-binary '{"ip":"10.2.2.2","host":"test1.com","replace":false,"ttl":1800}'

curl -sS -u admin:password -H 'Content-Type: application/json' -X POST http://127.0.0.1:8000/dnsmasq/add_host --data-binary '{"ip":"10.2.2.2","host":"test1.com","replace":false}'

curl -sS -u admin:password -H 'Content-Type: application/json' -X POST http://127.0.0.1:8000/dnsmasq/add_host --data-binary '{"ip":"10.2.2.2","host":"only-this.com","replace":true}'

curl -sS -u admin:password -X GET http://127.0.0.1:8000/dnsmasq/all

curl -sS -u admin:password -X POST http://127.0.0.1:8000/dnsmasq/export_now

curl -sS -u admin:password -X DELETE http://127.0.0.1:8000/dnsmasq/10.2.2.2/test.com

curl -sS -u admin:password -X DELETE http://127.0.0.1:8000/dnsmasq/10.2.2.2
