#!/usr/bin/env bash
#
# nama_om_nmap_recon.sh
# Consolidated nmap reconnaissance script for *.nama.om
# Combines all nmap-based checks from Phase 2 (Network Exposure Scanning)
# of the EASM Reconnaissance Guide into a single run.
#
# Usage:
#   ./nama_om_nmap_recon.sh <target> [subdomains_file]
#
#   <target>          Domain or IP to scan (e.g. nama.om)
#   [subdomains_file] Optional file with one subdomain per line, to scan
#                      each with the same checks (from your Phase 1 output)
#
# Requires: nmap (with NSE scripts), run with sudo for -O and some scripts.
# Only run this against assets you are authorized to test.

set -euo pipefail

TARGET="${1:-}"
SUBS_FILE="${2:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> [subdomains_file]"
    exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="nmap_recon_${TARGET}_${TS}"
mkdir -p "$OUTDIR"

echo "[*] Output directory: $OUTDIR"
echo "[*] Target: $TARGET"
echo

run() {
    local desc="$1"
    local outfile="$2"
    shift 2
    echo "[*] $desc"
    # "$@" is the actual nmap command; failures on one scan shouldn't kill the rest
    "$@" > "$OUTDIR/$outfile" 2>&1 || echo "    -> non-zero exit, see $outfile"
}

scan_target() {
    local host="$1"
    local prefix="$2"

    echo "=================================================="
    echo " Scanning: $host"
    echo "=================================================="

    # --- 2.1 Port Scanning & Service Enumeration ---
    run "2.1a Top-1000 port scan w/ version+default scripts" \
        "${prefix}_2.1a_top1000.txt" \
        nmap -sV -sC -oN /dev/stdout "$host"

    run "2.1b Full port scan (all 65535) w/ OS detect + vuln scripts" \
        "${prefix}_2.1b_fullscan_vuln.txt" \
        nmap -p- -sV -sC -O -A --script vuln -oN /dev/stdout "$host"

    run "2.1c Fast full-port scan w/ banner/http-title/ssl-ciphers" \
        "${prefix}_2.1c_fast_banners.txt" \
        nmap -p- -sV --script banner,http-title,ssl-enum-ciphers -oN /dev/stdout "$host"

    # --- 2.2 High-Risk Exposed Services ---
    run "2.2 High-risk services (RDP/SMB/SSH/Telnet/FTP/VNC/SNMP/rsync/NFS)" \
        "${prefix}_2.2_highrisk.txt" \
        nmap -p 21,22,23,139,161,445,873,2049,3389,5900 -sV -sU \
             --script "ftp-anon,smb-os-discovery,smb-vuln-*,ssh2-enum-algos,ssh-hostkey,snmp-brute,snmp-info,nfs-ls,nfs-showmount" \
             -oN /dev/stdout "$host"

    # --- 2.3 Exposed Databases & Caches ---
    run "2.3 Databases & caches (Mongo/Elastic/Redis/Memcached/MySQL/Postgres/MSSQL/CouchDB/Kibana)" \
        "${prefix}_2.3_databases.txt" \
        nmap -p 27017,9200,6379,11211,3306,5432,1433,5984,5601 -sV -sU \
             --script mysql-info -oN /dev/stdout "$host"

    # --- 2.4 Container & Orchestration Infrastructure ---
    run "2.4 Containers/orchestration (Docker/K8s API/Kubelet/etcd/Jenkins/GitLab runner)" \
        "${prefix}_2.4_containers.txt" \
        nmap -p 2375,2376,6443,10250,2379,2380,8080,8443,8081 -sV -oN /dev/stdout "$host"

    # --- 2.5 Edge & VPN Appliance Exposure ---
    run "2.5 Edge/VPN appliance mgmt interfaces (443/8443 ssl+http-title)" \
        "${prefix}_2.5_edge_vpn.txt" \
        nmap -p 443,8443 -sV --script ssl-enum-ciphers,http-title -oN /dev/stdout "$host"

    # --- 2.6 Managed File Transfer Exposure ---
    run "2.6 Managed file transfer (MOVEit/GoAnywhere/Cleo)" \
        "${prefix}_2.6_mft.txt" \
        nmap -p 443,8443,8001,9001,5080,5443 -sV -oN /dev/stdout "$host"

    # --- 2.7 Exposed Admin Interfaces ---
    run "2.7 Admin interfaces (routers/printers/cams/NAS/iDRAC/iLO/IPMI)" \
        "${prefix}_2.7_admin_ifaces.txt" \
        nmap -p 80,443,554,623,3000,5900,8080,8443,9000 -sV -oN /dev/stdout "$host"

    # --- 2.8 ICS/SCADA & OT Protocol Exposure ---
    run "2.8 ICS/SCADA/OT protocols (Modbus/DNP3/BACnet/S7comm/EtherNet-IP)" \
        "${prefix}_2.8_ics_scada.txt" \
        nmap -p 102,502,2222,20000,44818 -sU -sV --script "" -oN /dev/stdout "$host" \
        ; nmap -p 47808 -sU -oN "$OUTDIR/${prefix}_2.8b_bacnet.txt" "$host" >/dev/null 2>&1 || true

    # --- 2.9 DDoS Amplification Services ---
    run "2.9 DDoS amplification (open DNS resolver/NTP monlist/SSDP/CLDAP)" \
        "${prefix}_2.9_amplification.txt" \
        nmap -p 53,123,389,1900 -sU --script dns-recursion,ntp-monlist -oN /dev/stdout "$host"

    # --- 2.10 Origin IP / WAF probing helper (not nmap, kept for completeness) ---
    {
        echo "=== 2.10 CDN/WAF header check for $host ==="
        curl -sk -v "https://$host" 2>&1 | grep -i "cf-\|x-cdn\|powered by" || echo "no CDN/WAF headers matched"
    } > "$OUTDIR/${prefix}_2.10_waf_headers.txt" 2>&1 || true

    echo
}

# --- Scan the primary target ---
scan_target "$TARGET" "root"

# --- Optionally scan each subdomain from a discovery file (Phase 1 output) ---
if [[ -n "$SUBS_FILE" && -f "$SUBS_FILE" ]]; then
    echo "[*] Subdomain file provided: $SUBS_FILE"
    i=0
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        i=$((i+1))
        scan_target "$sub" "sub${i}_$(echo "$sub" | tr -c 'A-Za-z0-9._-' '_')"
    done < "$SUBS_FILE"
fi

echo "[*] Done. All output saved under: $OUTDIR"
