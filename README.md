WHAT IS MOD_EVASIVE?
====================

mod_evasive is a module for the Apache HTTP Server to provide evasive
action in the event of a (D)DoS or brute force attack.

Detection is performed by storing objects containing IPs and URIs in a
global cache, and denying clients from any of the following:

- Requesting a distinct page over a configurable threshold within a
  defined interval.
- Requesting any page on a distinct site over a configurable threshold
  within a defined interval.
- Making any requests while being blocked.


INSTALLATION
============

1. `make`
2. `sudo make install`
3. `sudo systemctl restart apache2  # on Debian and derivatives`


CONFIGURATION
=============

The module has to be explicitly enabled per virtual host context with
`DOSEnable`. In addition, a Shared Object Cache must be specified using
`DOSCache` (and the relevant module must be enabled). The following
excerpt also shows the default values of the other directives, which
are optional:
```
<VirtualHost *:*>
	DOSEnable          on
	DOSCache           shmcb
	DOSPageCount       2
	DOSSiteCount       50
	DOSPageInterval    1
	DOSSiteInterval    1
	DOSBlockingPeriod  10
</VirtualHost>
```

DOSPageCount
------------

This is the threshold for the number of requests for the same page (or
URI) per page interval. Once the threshold for that interval has been
exceeded, the IP address of the client will be added to the blocking list.

DOSSiteCount
------------

This is the threshold for the total number of requests for any object
by the same client on the same listener per site interval. Once the
threshold for that interval has been exceeded, the IP address of the
client will be added to the blocking list.

DOSPageInterval
---------------

The interval for the page count threshold in seconds.

DOSSiteInterval
---------------

The interval for the site count threshold in seconds.

DOSBlockingPeriod
-----------------

The blocking period is the amount of time (in seconds) that a client will
be blocked for if they are added to the blocking list. During this time,
all subsequent requests from the client will result in a 429 (Too Many
Requests) and the timer being reset (e.g. another 10 seconds). Since
the timer is reset for every subsequent request, it is not necessary to
have a long blocking period; in the event of a DoS attack, this timer
will keep getting reset.

DOSWhitelist
------------

IP addresses of trusted clients can be whitelisted to insure they
are never denied. The purpose of whitelisting is to protect software,
scripts, local searchbots, or other automated tools from being denied
for requesting large amounts of data from the server. Whitelisting
should *not* be used to add customer lists or anything of the sort,
as this will open the server to abuse. This module is very difficult to
trigger without performing some type of malicious attack, and for that
reason it is more appropriate to allow the module to decide on its own
whether or not an individual customer should be blocked.

To whitelist an address (or range) add entries to the configuration in
the following fashion:
```
DOSWhitelist  127.0.0.1
DOSWhitelist  172.16.1.*
```

Wildcards `?` or `*` can be utilized. This directive may be issued up
to 10 times.


TESTING
=======

Want to make sure it's working? Run `test.pl`, and view the response
codes. It's best to run it several times on the same machine as the
web server until you get 429 (Too Many Requests) messages. Some larger
servers with high child counts may require more of a beating than smaller
servers before blacklisting addresses.

Please don't use this script to DoS others without their permission.


