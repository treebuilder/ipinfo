# ipinfo
Script to quickly enrich an IP address


#### INPUT

  IP address

---

#### OUTPUT

IP GeoCC ShoCC rvAS ShoAS rvCIDR ShoORG DNS ShoDNS ShoPorts ShoTags ShoVulns

 * IP: IP address, taken from argv[1]
 * GeoCC: country code according to MaxMind GeoIP2 country database
 * ShoCC: country code according to Shodan
 * rvAS: ASN, per RouteViews MRT/RIB BRP database
 * ShoAS: ASN from Shodan
 * rvCIDR: CIDR range for the AS, per RouteViews
 * ShoORG: AS Organization name, per Shodan
 * DNS:  Reverse DNS lookup result
 * ShoDNS: hostnames for IP, per Shodan
 * ShoPorts:  Open ports for IP, from Shodan
 * ShoTags: Any associated Shodan tags
 * ShoVulns: Any known positive or negative vulnerability test results, per Shodan
    

---


#### REQUIRES

 * dnspython
 * geoip2
 * pyasn
 * shodan

 * up-to-date databases for geoip2 and pyasn (see their docs)
 * API key for shodan





