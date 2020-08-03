### obfs4proxy/meek_lite utls fork
#### Yawning Angel (yawning at schwanenlied dot me)

### What?

This is a fork of [utls][1] for the specific purpose of improving
obfs4proxy's meek_lite transport.

Functional differences:
 * Go v1.11 module metadata files have been added.
 * The handshake no longer fails if the remote server selects a curve
   that is not the 0th preferred curve (X25519).  This issue is primarily
   observable with the Azure host used for the Tor Browser meek bridge,
   and the `HelloFirefox_63` profile.
 * The handshake no longer fails against servers that support the
   [TLS Certificate Compression][2] draft.
 * `HelloGolang` is totally busted, and no longer resembles `crypto/tls`.
 * The AES block cipher and GHASH implementation will be timing
   side-channel safe on architectures where the `crypto/aes` one is
   not.

### Why?

I was bored and it was an easy way to make meek_lite less awful.

### Why don't you upstream the changes?

It's a pet project done in my spare time and I want to use a
[strong/viral][3] copyleft license for the vast majority of my pet
projects going forward.

I used to have a more liberal view on licensing but certain entities have
ruined it for everybody.  The portions of the code that I have not written
or altered are naturally under the original license.

### You changed something and broke my project!

Your tears are delicious, and your code will burn.

[1]: https://github.com/refraction-networking/utls
[2]: https://datatracker.ietf.org/doc/draft-ietf-tls-certificate-compression/
[3]: https://www.gnu.org/licenses/gpl.txt
