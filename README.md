# modsec-ufw-bouncer

A small systemd service for Ubuntu that tails ModSecurity logs, tracks repeated
failures from the same client IP over a configurable window, and inserts a
temporary UFW deny. Policies are configurable per ModSecurity rule ID.

## Files

- `modsec-ufw-bouncer.py` — daemon/runtime
- `modsec-ufw-bouncer.conf` — configuration template
- `modsec-ufw-bouncer.service` — systemd unit
- `install.sh` — root installer

## Install

```bash
cd /home/thomas/Projects/modsec-ufw-bouncer
sudo ./install.sh
```

The installer preserves an existing `/etc/modsec-ufw-bouncer.conf`. It does not
start the service automatically, so you can review the configuration first.

## Configure

Edit:

```bash
sudo nano /etc/modsec-ufw-bouncer.conf
```

Set the real ModSecurity log paths:

```ini
[general]
log_paths = /var/log/apache2/modsec_audit.log /var/log/apache2/error.log
```

A rule-specific policy looks like:

```ini
[rule:920280]
threshold = 3
window = 300
block_duration = 600
```

That means: if one client IP produces at least 3 events for rule `920280`
within 300 seconds, UFW blocks that IP for 600 seconds. Set
`block_duration = 0` for a permanent deny. Rules with no section use
`default_threshold`, `default_window`, and `default_block_duration`.

To only monitor selected rule IDs:

```ini
enabled_rule_ids = 920280,932100,949110
```

Leave `enabled_rule_ids` empty to monitor every rule ID seen in the logs.

Whitelist IPs/CIDRs that must never be blocked:

```ini
whitelist = 127.0.0.1 ::1 10.0.0.0/8
```

## Test before going live

Dry run reads available new log data, evaluates the rules, and prints what
would be blocked. It does not call UFW or update state:

```bash
sudo modsec-ufw-bouncer.py --dry-run -v
```

Then review status and logs after enabling:

```bash
sudo systemctl enable --now modsec-ufw-bouncer.service
systemctl status modsec-ufw-bouncer.service
journalctl -u modsec-ufw-bouncer.service -f
sudo ufw status numbered
```

## Firewall behavior

The daemon inserts rules near the top of the UFW ruleset:

```text
ufw insert 1 deny from <IP> to any comment 'modsec-ufw-bouncer rule=...'
```

When the block expires, it removes the deny. Expired or permanently blocked
entries are tracked in `/var/lib/modsec-ufw-bouncer/state.json`.

## Safety notes

- Ensure your own office, VPN, CDN, and monitoring IPs are whitelisted.
- Be careful when assigning a low `threshold` to broad scanning rules.
- UFW must be enabled; this service adds rules but does not enable UFW.
- If you manually remove a UFW rule while the state still tracks it, the daemon
  will attempt removal again on expiration and log an error.
- `--dry-run` reads once and does not update the persisted state file, so you can
  rerun it; `--once` does update state.
