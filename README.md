# ptrcheck

Check that every address record (`A`/`AAAA`) in a DNS zone has a valid and
acceptable corresponding `PTR` record.

## Introduction

Remembering to set correct reverse DNS is sometimes hard, yet sometimes it is
very important, especially if you are sending email from those addresses.
Other times it is just a matter of pride! `ptrcheck` allows you to run
constant, bulk checks on a whole DNS zone to give assurance that all `PTR`
records are as they should be.

### Typical run

![typical]

[typical]: doc/typical.png "Output of a typical run of ptrcheck"

[(Plain text version)](doc/typical.txt)

### Verbose run

Without the verbose option this would actually have been silent as all `PTR`s
were "good".

![verbose]

[verbose]: doc/verbose.png "Output of a verbose run of ptrcheck"

[(Plain text version)](doc/verbose.txt)

And another verbose run, this time with only partial success.

![verbose2]

[verbose2]:
  doc/verbose2.png
  "Output of a verbose run of ptrcheck, showing only partial success"

[(Plain text version)](doc/verbose2.txt)

## Installation

Some binaries are available at the
[releases page of GitHub](https://github.com/grifferz/ptrcheck-rs/releases).

This is a Rust application, so after cloning this repo you can build it from
source with `cargo` like:

```bash
$ cargo build --release
```

The binary should then be found in the `target/release/` directory. Put it on
your path or run it from anywhere.

## Usage

```
$ ptrcheck -h
ptrcheck 0.1.0
Andy Smith <andy-ptrcheck@bitfolk.com>

Check that all address records in a DNS zone have valid and acceptable
PTR records associated

Usage: ptrcheck [OPTIONS] --server <SERVER> --zone <ZONE>

Options:
  -b, --badre <BADRE>    Regular expression for unacceptable PTRs
  -c, --color <COLOR>    Use colored output [default: auto]
                         [possible values: auto, always, never]
  -s, --server <SERVER>  Server to do AXFR against (in form IP:port)
  -v, --verbose          Be more verbose
  -z, --zone <ZONE>      Zone to check PTR records for
  -h, --help             Print help
  -V, --version          Print version
```

The required arguments are `--server` and `--zone`. `ptrcheck` gets its zone
data by zone transfer (AXFR), so you'll need to be able to do a transfer from
a name server that is authoritative for your zone.

### Server to do zone transfer from

This is specified with `--server <SERVER>`. The `<SERVER>` part should be an
IP address and port number separated by a colon. IPv6 addresses should be
wrapped in square brackets. Hostnames are not supported.

Examples:

```
$ ptrcheck --server 127.0.0.1:53 --zone example.com
$ ptrcheck --server [::1]:53 --zone example.com
```

### Zone to check

This is specified with `--zone <ZONE>`. It should be the zone as it exists in
the DNS, which means for example that IDN domains would need to be converted
to [Punycode](https://en.wikipedia.org/wiki/Punycode).

### Detecting bad PTR content

The default behavior is to consider only missing (or unqueryable) `PTR`
records to be "bad". Often though, hosting providers supply default reverse
DNS when none is set by the customer, and these usually will resolve both
ways. Just checking that a `PTR` record exists may not be enough for your
purposes. In the case of a mail server, for example, it is a very bad idea to
operate with a "generic" reverse DNS of any kind.

To help with this the `--badre` option allows you to supply a regular
expression that identifies "bad" `PTR` content.

Example:

```
$ ptrcheck \
  --server [::1]:53 \
  --zone example.com \
  --badre 'linodeusercontent|vps\.ovh\.net'
```

### Use of DNS

`ptrcheck` does a zone transfer directly from the host and port that you
specify with `--server`, but it then queries for `PTR` records using your
normal system resolver as you have configured in `/etc/resolv.conf` (or
equivalent on Windows).

In particular this means:

- You'll get cached answers from your resolver if they are present
- Your resolver may have a different view of the Internet than the zone
  administrator expects. For example, if a public zone contains internal
  hostnames these may point at IP addresses you cannot ever resolve `PTR`
  records for, and that is not necessarily an error.

### Exit codes

- `0`
  - When no problems were detected
- `1`
  - When any "bad" `PTR` records were detected
- `2`
  - Initial zone transfer request was refused

## Limitations

### Things I'll probably try to improve

These things affect me so I will probably get around to improving them at some
point.

- This is synchronous, single-threaded code. A zone is transferred and then
  individual `PTR` queries are made one after another with default timeouts.
  This is quite slow. Async would likely improve this.
- Should be able to specify a host name for the DNS server to query.
- Port should default to 53 if not supplied.
- There should be an option for a silent mode. You would use the exit code to
  tell if there were a problem or not.
- An option to ignore some address blocks would be useful, in order to exclude
  [the RFC1918 private blocks](https://en.wikipedia.org/wiki/Private_network#Private_IPv4_addresses)
  from checking, for example.
- There's no point in doing another check of a zone if the zone content hasn't
  changed. It might be possible to hook this into a DNS server to trigger
  that, or just have it keep track of which zone serial numbers it has already
  checked.
- Zone content should be optionally obtainable from a file instead of a zone
  transfer. This would be a bit faster, would facilitate more testing, and
  would make the tool useful for people who don't have AXFR access to their
  name servers.
- Did I say testing? There's no tests here. There really should be, but I
  wasn't up to mocking a DNS server and I wanted to get something achieved.

### Known issues that aren't a personal priority

These limitations don't bother me for my use cases so I'm unlikely to fix
them, but I still welcome assistance.

- There's no [TSIG](https://en.wikipedia.org/wiki/TSIG) support so zone
  transfers are authenticated by IP address alone.
- There isn't any support for DNS-over-TLS or DNS-over-HTTPS either.
- I can imagine _someone_ wanting to specify a different resolver to use other
  than what they have in their `/etc/resolv.conf`, but it's not a need I have
  personally.
- `ptrcheck` currently only checks that there is _some_ `PTR` content. Some
  might like an optional stricter check that requires that a successful chain
  of `hostname1` → `IP` → `hostname2` → `IP` exist where `hostname1` and
  `hostname2` may or may not be the same thing, i.e. that at least one forward
  and reverse mapping is in agreement.

## Disclaimer

I'm not a proficient Rust developer. I did this just for practice and I'm well
aware that it contains some poor code, plus no doubt some more poor code that
I'm not yet aware of. I welcome constructive feedback and assistance, though I
may not be capable of acting upon it. Please contact me or file
[a GitHub issue](https://github.come/grifferz/ptrcheck-rs/issues) for any
bugs, feature requests or other feedback.

