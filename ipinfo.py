#!/usr/bin/env python

import sys
import dns.resolver
import dns.reversename
import geoip2.database
import pyasn
import shodan

'''
INPUT:
  IP address

OUTPUT:
  IP CC ASN CIDR domainname
    IP address, country code according to MaxMind
    database, ASN and CIDR range according to 
    RouteViews MRT/RIB BRP database.

REQUIRES:
  dnspython
  geoip2
  pyasn
  shodan

  up-to-date databases for geoip2 and pyasn (see their docs)
  API key for shodan



http://www.cs.newpaltz.edu/%7Epletcha/NET_PY/the-protocols-tcp-ip-illustrated-volume-1.9780201633467.24290.pdf
pyasn_util_convert.py --single rib.20171201.1600.bz2 ipasn.dat
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz


'''


PATH = '/PATH/TO/DATA/FILES'



gi = geoip2.database.Reader(PATH + '/GeoLite2-Country.mmdb')
asndb = pyasn.pyasn(PATH + '/ipasn.dat')
ip = sys.argv[1].strip()

SHODAN_API_KEY = "INSERT YOUR SHODAN API KEY HERE"
api = shodan.Shodan(SHODAN_API_KEY)

try:
  asndata = asndb.lookup(ip)
except:
  ip = '127.0.0.1'
  asndata = asndb.lookup(ip)
cc = gi.country(ip)
cc = cc.country.iso_code
try:
  host = api.host(ip)
  sorg = host.get('org')
  sports = host.get('ports')
  stags = host.get('tags')
  shostnames = host.get('hostnames')
  scc = host.get('country_code')
  sasn = host.get('asn')
  svulns = host.get('vulns')
  
except:
  sorg = 'None'
  sports = 'None'
  stags = 'None'
  shostnames = 'None'
  scc = 'None'
  sasn = 'None'
  svulns = 'None'


asn = asndata[0]
cidr = asndata[1]

print 'IP GeoCC ShoCC rvAS ShoAS rvCIDR ShoORG DNS ShoDNS ShoPorts ShoTags ShoVulns'
answer = "%s|%s|%s|%s|%s|%s|%s|" % (ip, str(cc), str(scc), str(asn), str(sasn), str(cidr), str(sorg))
try:
  for a in dns.resolver.query(dns.reversename.from_address(ip), 'PTR'):
    answer += "%s|" % a 
except:
  answer += 'None|'
answer += "%s|%s|%s|%s" % (shostnames,sports,stags,svulns)
print answer


