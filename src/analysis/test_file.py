from ipv6_analyzer import IPv6Analyzer

tests = [
    "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
    "0000:0000:0000:0000:0000:0000:0000:0001",
    "2001:0000:0000:0001:0000:0000:0000:0001"
]
ipa = IPv6Analyzer()
for t in tests:
    print(t, "→", ipa.compress_address(t))
