# dns-client

Simple DNS client that supports recursive queries.

Example output:
```
---- Request ----
Header: { Id: 12345, Flags: { QR: 0, OpCode: 0, AA: 0, TC: 0, RD: 1, RA: 0, Z: 0, RCode: 0 }, QdCount: 1, AnCount: 0, NsCount: 0, ArCount: 0 }
Questions: [ 
  { QName: echevarria.io, QType: 2, QClass: 1 }
]

---- Response ----
Header: { Id: 12345, Flags: { QR: 1, OpCode: 0, AA: 0, TC: 0, RD: 1, RA: 1, Z: 0, RCode: 0 }, QdCount: 1, AnCount: 2, NsCount: 0, ArCount: 0 }
Questions: [
  { QName: echevarria.io, QType: 2, QClass: 1 }
]
Answers: [
  { Name: echevarria.io, Type: 2, Class: 1, TTL: 19818, RDLength: 24, RData: lily.ns.cloudflare.com }
  { Name: echevarria.io, Type: 2, Class: 1, TTL: 19818, RDLength: 8, RData: miles.ns.cloudflare.com }
]
```
