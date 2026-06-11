---
name: dns-lookup-check
description: Performs a DNS lookup for a given domain name to resolve it to IP addresses.
parameters:
  - name: domain
    type: string
    description: The domain name to resolve (e.g., 'google.com').
    required: true
---

# DNS Lookup Check
This skill allows the operator to resolve a domain name to its associated IP addresses, which is helpful during network incident response to identify the destination of network traffic.