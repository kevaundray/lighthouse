# Running the zkAttester client

### WARNING: THIS CODE IS EXPERIMENTAL - FOR DEMO ONLY

**Steps to run the modified Lighthouse client:**

1. Clone the repo: `https://github.com/ethproofs/lighthouse`
2. `git checkout ethproofs/zkattester-demo`
3. Run `make` to build the new binary
4. Install the new binary: `sudo cp ~/.cargo/bin/lighthouse /usr/local/bin/`
5. Install Docker if needed
6. For the dummy EL run: `docker build -f dummy_el/Dockerfile -t dummy_el:latest .`
7. Run (e.g. Linux Debian):

```bash
docker run -d \
    -p 8551:8551 \
    --name dummy-el \
    dummy_el:latest \
    /usr/local/bin/dummy_el \
   --port 8551 \
    --jwt-secret /path/to/jwt.hex
```

8. Stop your EL and CL if needed
9. Start your LH client with the `--activate-zkvm` flag:

```bash
   lighthouse bn \
    --mainnet \
    --execution-endpoint http://localhost:8551 \
    --execution-jwt /path/to/jwt.hex \
    --activate-zkvm \
    --debug-level debug \
    # ...other flags
```

10. For debug logs: `sudo journalctl -u lighthouse-beacon -f | grep -i "Ethproofs"`
