# hello-requests
Easy to use golang based request client made to be indistinguishable from popular browser/OS combinations (When configured properly)

Features:
- Mimic TLS client hello (most credit to https://github.com/refraction-networking/utls)
- Mimic HTTP2 frames from modern browsers
- Mimic HTTP2 header order from modern browsers
- Custom header ordering (Outside of the H2 headers)
- Custom idle connection timeouts
- Custom request timeouts
- Proxy support
- JSON/Form Data/Query String body building
- Byte request bodies can be passed in as Base64


Noted:
- I haven't updated any of the fingerprints in a while (mimic/mimic.go)
- If no `MimicBrowser` string is passed it defaults to chrome
- If you don't pass some important headers it may cause issues
- Some domains may handle the TLS client hello differently and cause TLS errors
