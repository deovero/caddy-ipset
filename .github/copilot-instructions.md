This is a Caddy HTTP matcher module that matches the client_ip against Linux ipset lists using native netlink communication.
Since it requires the Linux ipset kernel module, it only works on Linux systems.

We have a Docker container available for testing.
After change please run tests using:

```bash
make test
```

To build:
```bash
make build
```

To benchmark:
```bash
make bench
```

After making bigger changes or new features, update `CHANGELOG.md`.

When we reach the CoPilot rate limit please continue.
