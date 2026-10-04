# Move Hermes OSINT Hybrid v1.3.9 to another machine

The release ZIP contains code, modules, references, templates, and documentation. It does **not** contain API secrets or prior case data unless you copy those separately.

## 1. Copy the release ZIP

Move `hermes_osint_hybrid_v1_3_9.zip` to the destination machine and unpack it:

```bash
unzip hermes_osint_hybrid_v1_3_9.zip
cd hermes_osint_hybrid_v1_3_9
```

## 2. Recommended Kali/Linux utilities

The Python runner is standard-library based, but these local tools improve coverage:

```bash
sudo apt update
sudo apt install -y dnsutils whois openssl postgresql-client
```

Optional integrations such as Shodan and Sherlock require their own local CLI installation/configuration.

## 3. Install the Hermes skill

```bash
bash bin/install-hermes.sh
```

Default destination:

```text
~/.hermes/skills/research/osint-hybrid-investigation
```

The installer preserves an existing `cases/` directory during upgrades.

## 4. Re-create credentials locally

Do not copy secrets into chat, source control, or the release ZIP. On the destination machine create:

```bash
nano ~/.osint_keys
chmod 600 ~/.osint_keys
```

Supported names:

```bash
export NETLAS_API_KEY='...'
export CENSYS_PAT='...'
export URLSCAN_API_KEY='...'
export VT_API_KEY='...'
export SHODAN_API_KEY='...'
# optional
export HUNT_API_KEY='...'
export HUNT_IO_TOKEN='...'
export GREYNOISE_API_KEY='...'
```

Do **not** source this file before starting Hermes. The runner reads it privately inside its own process.

## 5. Preflight

```bash
python3 ~/.hermes/skills/research/osint-hybrid-investigation/bin/preflight.py
python3 ~/.hermes/skills/research/osint-hybrid-investigation/bin/domain_osint.py --self-check
```

Expected runner state:

```text
version: 1.3.9
execution_mode: canonical_runner
canonical_layout: True
```

## 6. Start Hermes normally

```bash
hermes
```

For a domain case, instruct Hermes to use the installed `osint-hybrid-investigation` skill and the canonical runner only.

## Optional: move previous cases

If you want old case artifacts on the new machine, copy the `cases/` directory separately to:

```text
~/.hermes/skills/research/osint-hybrid-investigation/cases/
```

Case data can contain sensitive investigative material. Protect it appropriately and do not bundle it with public releases.
