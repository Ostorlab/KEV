# Known Exploited Vulnerabilities (KEV) Detector

**KEV finds known exploited vulnerabilities on internet-facing systems in one scan.**
It is an Ostorlab agent group that combines five open-source scanners:

- **Agent Nuclei** — verified Nuclei templates for known exploited vulnerabilities.
- **Agent Tsunami** — Google Tsunami detectors for common exposed services.
- **Agent Nmap** — port and service discovery.
- **Agent Asteroid** — Ostorlab's remote CVE scanner.
- **Agent Metasploit** — auxiliary checks for selected vulnerabilities.

The group runs read-only detection checks. A finding means the target matches a
known-vulnerable condition. The group does not exploit, upload payloads, change
configuration or authenticate. A clean scan does not prove a target is patched.

| Coverage | Count |
| --- | ---: |
| CVEs in KEV's existing coverage | 893 |
| Additional CVEs detected by the current Agent Asteroid release | 203 |
| **Unique CVEs covered by the agent group** | **1096** |
| Non-CVE exposure checks in the KEV table | 25 |
| Agent Asteroid offline-inventory CVEs (manual, not run by this group) | 85 |

_Coverage snapshot: 8 November 2026._

CISA KEV entries that cannot be checked safely or remotely remain listed in
[docs/coverage-status.md](docs/coverage-status.md). At this snapshot, 1,205
entries are not detected and 1 is in progress.

## What it detects

- **Actively exploited vulnerabilities** from the CISA KEV catalog, when a safe
  remote check exists.
- **Common exposed services** covered by Google Tsunami, such as exposed Docker
  APIs, Jenkins, Jupyter, Kubernetes, Redis and Spring Boot Actuator.
- **Agent Asteroid's 371 remote CVE checks**, including web applications, VPNs,
  firewalls, mail servers, databases and network appliances.
- **Selected Metasploit auxiliary checks** where a Nuclei template is not
  available.

The coverage table also includes the **2026-11-07 Nuclei backlog import**: 255
CVEs with exact source paths, hashes and registrations in
[`coverage/2026-11-07/`](coverage/2026-11-07/). Templates tagged `intrusive`
are excluded because they modify the target. A finding leaves exploitability
unconfirmed when the check can only establish potential exposure.

## Requirements

- Python 3.9 or greater.
- Docker, to run scans locally. See the
  [Docker installation guide](https://docs.docker.com/get-docker/).

## Install

```shell
pip install -U ostorlab
```

This installs the `oxo` command. The same CLI is also available as `ostorlab`.

## How to use it

### Scan an IP address

```shell
oxo scan run --install -g agent_group.yaml ip 8.8.8.8
```

Scan more than one address by separating them with spaces:

```shell
oxo scan run --install -g agent_group.yaml ip 8.8.8.8 1.1.1.1 4.4.4.0/24
```

### Scan a domain name

```shell
oxo scan run --install -g agent_group.yaml domain-name www.example.com
```

### Scan a link

```shell
oxo scan run --install -g agent_group.yaml link --url https://www.example.com --method GET
```

### Include subdomains

Add `subfinder` and/or `dnsx` to `agent_group.yaml` to enumerate and target
subdomains:

```yaml
agent:
  ...
  - key: agent/ostorlab/subfinder
  - key: agent/ostorlab/dnsx
```

> [!TIP]
> The default settings use public DNS servers, which can affect enumeration
> results for very large domains due to rate limiting or caching. Set custom
> resolvers in the Amass and Subfinder agent arguments if needed.

### Run with Docker

```shell
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v ./agent_group.yaml:/agent_group.yaml \
  ostorlab/oxo:latest scan run --install -g /agent_group.yaml \
  link --url https://www.example.com --method GET
```

The Docker image uses `oxo` as its entrypoint, and the Docker socket must be
mounted so `oxo` can start the agents on the host.

### Read the results

```shell
oxo scan list
oxo vulnz list -s <scan-id>
oxo vulnz describe -v <vuln-id>
```

## Coverage

### Detected CVEs

The table below combines KEV's existing coverage (893 CVEs,
including earlier Agent Asteroid checks) with the 203
additional CVEs detected by the current Agent Asteroid release:
**1096 unique CVEs**. The detector column shows which scanner reports
each CVE.

| Year | KEV existing | Added by Agent Asteroid | Total |
| --- | ---: | ---: | ---: |
| 2026 | 227 | 150 | 377 |
| 2025 | 107 | 25 | 132 |
| 2024 | 157 | 17 | 174 |
| 2023 | 80 | 5 | 85 |
| 2022 | 51 | 2 | 53 |
| 2021 | 72 | 2 | 74 |
| 2020 | 51 | 0 | 51 |
| 2019 | 47 | 1 | 48 |
| 2018 | 28 | 0 | 28 |
| 2017 | 34 | 0 | 34 |
| 2016 | 8 | 1 | 9 |
| 2015 | 7 | 0 | 7 |
| 2014 | 8 | 0 | 8 |
| 2013 | 6 | 0 | 6 |
| 2012 | 3 | 0 | 3 |
| 2011 | 1 | 0 | 1 |
| 2010 | 5 | 0 | 5 |
| 2009 | 1 | 0 | 1 |
| **Total** | 893 | 203 | 1096 |

<details><summary><b>2026 — 377 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2026-0257 | Palo Alto Networks PAN-OS Authentication Bypass Vulnerability | Nuclei |
| CVE-2026-0545 | MLflow CVE-2026-0545 job authentication bypass | Agent Asteroid |
| CVE-2026-0650 | OpenFlagr CVE-2026-0650 authentication bypass | Agent Asteroid |
| CVE-2026-0702 | VidShop for WooCommerce <= 1.1.4 - SQL Injection | Nuclei |
| CVE-2026-0768 | Langflow <=1.2.x - Unauthenticated Remote Code Execution via validate_code | Nuclei |
| CVE-2026-0770 | Langflow Inclusion of Functionality from Untrusted Control Sphere Vulnerability | Nuclei |
| CVE-2026-0920 | LA-Studio Element Kit for Elementor (CVE-2026-0920) | Agent Asteroid |
| CVE-2026-0926 | Prodigy Commerce (CVE-2026-0926) | Agent Asteroid |
| CVE-2026-1207 | Django RasterField - SQL Injection | Nuclei |
| CVE-2026-1281 | Ivanti Endpoint Manager Mobile (EPMM) Code Injection Vulnerability | Nuclei |
| CVE-2026-1306 | midi-Synth (CVE-2026-1306) | Agent Asteroid |
| CVE-2026-1340 | Ivanti Endpoint Manager Mobile (EPMM) Code Injection Vulnerability | Nuclei |
| CVE-2026-1357 | WPvivid Backup & Migration <= 0.9.123 - Unauthenticated Arbitrary File Upload to RCE | Nuclei + Agent Asteroid |
| CVE-2026-1405 | Slider Future (CVE-2026-1405) | Agent Asteroid |
| CVE-2026-1492 | User Registration & Membership (CVE-2026-1492) | Agent Asteroid |
| CVE-2026-1557 | WP Responsive Images <= 1.0 - Arbitrary File Read | Nuclei |
| CVE-2026-1581 | wpForo Forum <= 2.4.14 - SQL Injection | Nuclei |
| CVE-2026-1603 | Ivanti Endpoint Manager (EPM) Authentication Bypass Vulnerability | Nuclei |
| CVE-2026-1731 | BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA) OS Command Injection Vulnerability | Nuclei |
| CVE-2026-1830 | Quick Playground (CVE-2026-1830) | Agent Asteroid |
| CVE-2026-1980 | WPBookit (CVE-2026-1980) | Agent Asteroid |
| CVE-2026-2025 | Mail Mint < 1.19.5 - Unauthenticated Email Disclosure | Nuclei |
| CVE-2026-2262 | Easy Appointments <= 3.12.21 - Information Disclosure | Nuclei |
| CVE-2026-2413 | Ally – Web Accessibility & Usability <= 4.0.3 - SQL Injection | Nuclei |
| CVE-2026-2416 | Geo Mashup (CVE-2026-2416) | Agent Asteroid |
| CVE-2026-2599 | WordPress Contact Form Entries <= 1.4.7 - Unauthenticated PHP Object Injection | Nuclei |
| CVE-2026-2635 | MLflow default administrator credential permits account read access | Agent Asteroid |
| CVE-2026-2652 | MLflow < 3.10.0 - Authentication Bypass on FastAPI Routes | Nuclei |
| CVE-2026-2699 | Progress ShareFile Storage Zones Controller - Authentication Bypass | Nuclei |
| CVE-2026-3055 | Citrix NetScaler Out-of-Bounds Read Vulnerability | Nuclei |
| CVE-2026-3296 | Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder (CVE-2026-3296) | Agent Asteroid |
| CVE-2026-3326 | XStore Theme < 9.7.3 - SQL Injection | Nuclei |
| CVE-2026-3395 | MaxSite CMS <=109.1 - Remote Code Execution | Nuclei |
| CVE-2026-3396 | WCAPF WooCommerce Ajax Product Filter - SQL Injection | Nuclei |
| CVE-2026-3576 | Planyo Online Reservation System <= 3.0 - Arbitrary File Read | Nuclei |
| CVE-2026-3584 | Kali Forms (CVE-2026-3584) | Agent Asteroid |
| CVE-2026-3844 | Breeze Cache (CVE-2026-3844) | Agent Asteroid |
| CVE-2026-3891 | Pix for WooCommerce (CVE-2026-3891) | Agent Asteroid |
| CVE-2026-4020 | Gravity SMTP WordPress Plugin - Sensitive Information Exposure | Nuclei |
| CVE-2026-4060 | Geo Mashup (CVE-2026-4060) | Agent Asteroid |
| CVE-2026-4106 | HT Mega < 3.0.7 - Sensitive Information Disclosure | Nuclei |
| CVE-2026-4257 | Contact Form by Supsystic (CVE-2026-4257) | Agent Asteroid |
| CVE-2026-4858 | Mattermost CVE-2026-4858 (advertised release) | Agent Asteroid |
| CVE-2026-5032 | W3 Total Cache <= 2.9.3 - Unauthenticated Dynamic Security Token Disclosure | Nuclei |
| CVE-2026-5073 | WordPress ARMember Premium <= 7.3.1 - Unauthenticated SQL Injection | Nuclei |
| CVE-2026-6279 | Avada Builder (fusion-builder) <= 3.15.2 - Unauthenticated RCE via PHP Function Injection | Nuclei |
| CVE-2026-6377 | Next4Biz CSM - Arbitrary File Read via DownloadFileHandler | Nuclei |
| CVE-2026-6639 | AI Copilot Content Generator <=1.4.6 - Unauthenticated Task Data Exposure | Nuclei |
| CVE-2026-7873 | Langflow CVE-2026-7873 code-validation RCE | Agent Asteroid |
| CVE-2026-8037 | Progress LoadMaster Command Injection Vulnerability | Nuclei |
| CVE-2026-8181 | Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) (CVE-2026-8181) | Agent Asteroid |
| CVE-2026-8679 | WordPress AudioIgniter <= 2.0.2 - Unauthenticated IDOR | Nuclei |
| CVE-2026-9082 | Drupal Core SQL Injection Vulnerability | Nuclei |
| CVE-2026-9103 | Langflow CVE-2026-9103 auto-login token issuance | Agent Asteroid |
| CVE-2026-9198 | IBM Langflow Code Injection Vulnerability | Nuclei |
| CVE-2026-9290 | WP User Manager – User Profile Builder & Membership (CVE-2026-9290) | Agent Asteroid |
| CVE-2026-9506 | Bagisto <= 2.4.1 - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2026-9586 | Sangoma Switchvox SQL Injection Vulnerability | Nuclei |
| CVE-2026-9848 | Customer Support Ticket System & Helpdesk (CVE-2026-9848) | Agent Asteroid |
| CVE-2026-10520 | Ivanti Sentry OS Command Injection Vulnerability | Nuclei |
| CVE-2026-10580 | Hippoo Mobile App for WooCommerce (CVE-2026-10580) | Agent Asteroid |
| CVE-2026-10768 | Drupal LocalGov Workflows < 1.6.0 - Information Disclosure | Nuclei |
| CVE-2026-10823 | YMC Filter WordPress - Unauthenticated Post Disclosure | Nuclei |
| CVE-2026-11387 | SMS Alert (CVE-2026-11387) | Agent Asteroid |
| CVE-2026-11801 | WPAdverts <= 2.3.2 - Information Disclosure | Nuclei |
| CVE-2026-12227 | Visual Composer <= 45.16.0 - Unauthenticated LFI | Nuclei |
| CVE-2026-12394 | MemberGlut (CVE-2026-12394) | Agent Asteroid |
| CVE-2026-12609 | Eclipse Theia - Unauthenticated Path Traversal | Nuclei |
| CVE-2026-12741 | WP Fast Total Search <= 1.80.280 - Unauthenticated Time-Based Blind SQL Injection | Nuclei |
| CVE-2026-13001 | Podlove Podcast Publisher (CVE-2026-13001) | Agent Asteroid |
| CVE-2026-13153 | Essential Blocks < 6.4.0 - Information Disclosure | Nuclei |
| CVE-2026-14483 | Realtyna Organic IDX plugin + WPL Real Estate (CVE-2026-14483) | Agent Asteroid |
| CVE-2026-15015 | MountDev AI MCP Connector for WordPress (CVE-2026-15015) | Agent Asteroid |
| CVE-2026-15409 | SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability | Nuclei |
| CVE-2026-15826 | User Profile Builder (CVE-2026-15826) | Agent Asteroid |
| CVE-2026-16232 | Check Point SmartConsole Improper Authentication Vulnerability | Nuclei |
| CVE-2026-18072 | Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded Backdoor Authentication Bypass | Nuclei |
| CVE-2026-18110 | Concrete CMS - User Enumeration | Nuclei |
| CVE-2026-18315 | TrueBooker (CVE-2026-18315) | Agent Asteroid |
| CVE-2026-18577 | N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability | Nuclei |
| CVE-2026-18937 | WordPress Broken Link Checker < 2.4.12 - Remote Code Execution | Nuclei |
| CVE-2026-19089 | Product Input Fields for WooCommerce (CVE-2026-19089) | Agent Asteroid |
| CVE-2026-19092 | Tutor LMS (CVE-2026-19092) | Agent Asteroid |
| CVE-2026-19598 | Pods - Custom Content Types and Fields (CVE-2026-19598) | Agent Asteroid |
| CVE-2026-19632 | TranslatePress (CVE-2026-19632) | Agent Asteroid |
| CVE-2026-19868 | SonicWall SonicOS SSLVPN Use of Single-factor Authentication Vulnerability | Agent Asteroid |
| CVE-2026-19900 | LB-LINK Routers - Unauthenticated Command Injection | Nuclei |
| CVE-2026-20079 | Cisco Firewall Management Center Authentication Bypass Using an Alternate Path or Channel Vulnerability | Nuclei |
| CVE-2026-20127 | Cisco Catalyst SD-WAN Controller and Manager Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2026-20131 | Cisco Secure Firewall Management Center (FMC) Software and Cisco Security Cloud Control (SCC) Firewall Management Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2026-20253 | Splunk Enterprise Missing Authentication for Critical Function Vulnerability | Nuclei |
| CVE-2026-21445 | Langflow CVE-2026-21445 monitoring authentication bypass | Agent Asteroid |
| CVE-2026-21589 | Atlassian Multiple Products Files or Directories Accessible to External Parties Vulnerability | Agent Asteroid |
| CVE-2026-21643 | Fortinet FortiClient EMS SQL Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-21858 | n8n CVE-2026-21858 unauthenticated file access | Agent Asteroid |
| CVE-2026-21859 | Mailpit < 1.28.3 - Server-Side Request Forgery | Nuclei |
| CVE-2026-21877 | n8n CVE-2026-21877 authenticated RCE | Agent Asteroid |
| CVE-2026-21891 | ZimaOS - Authentication Bypass | Nuclei |
| CVE-2026-22557 | UniFi Network Application - Path Traversal | Nuclei |
| CVE-2026-22739 | Spring Cloud Config Server - Path Traversal | Nuclei |
| CVE-2026-22769 | Dell RecoverPoint for Virtual Machines (RP4VMs) Use of Hard-coded Credentials Vulnerability | Agent Asteroid |
| CVE-2026-22778 | vLLM CVE-2026-22778 video-processing RCE chain | Agent Asteroid |
| CVE-2026-23482 | Blinko < 1.8.4 - Path Traversal | Nuclei |
| CVE-2026-23491 | InvoicePlane <= 1.6.3 - Arbitrary File Read | Nuclei |
| CVE-2026-23536 | Feast Feature Server <=0.58.0 - Arbitrary File Read | Nuclei |
| CVE-2026-23696 | Windmill CVE-2026-23696 folder SQL injection | Agent Asteroid |
| CVE-2026-23760 | SmarterTools SmarterMail Authentication Bypass Using an Alternate Path or Channel Vulnerability | Agent Asteroid |
| CVE-2026-24061 | GNU InetUtils Argument Injection Vulnerability | Agent Asteroid |
| CVE-2026-24207 | NVIDIA Triton Inference Server <= 26.02 - Authentication Bypass | Nuclei |
| CVE-2026-24423 | SmarterTools SmarterMail Missing Authentication for Critical Function Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-24898 | OpenEMR CVE-2026-24898 MedEx token disclosure | Agent Asteroid |
| CVE-2026-25231 | FileRise <= 3.3.0 - Unauthenticated File Read | Nuclei |
| CVE-2026-25512 | Group-Office CVE-2026-25512 TNEF command injection | Agent Asteroid |
| CVE-2026-25545 | Astro SSR - Server-Side Request Forgery | Nuclei |
| CVE-2026-25555 | OpenBullet2 <= 0.3.2 - Authentication Bypass | Nuclei |
| CVE-2026-25703 | NeuVector - Information Disclosure | Nuclei |
| CVE-2026-25892 | Adminer 4.6.2 - 5.4.1 Unauthenticated Persistent DoS | Nuclei |
| CVE-2026-26190 | Milvus - Unauthenticated Metrics API Access | Nuclei |
| CVE-2026-26216 | Crawl4AI < 0.8.0 - Unauthenticated Remote Code Execution via Hooks Parameter | Nuclei |
| CVE-2026-26265 | Discourse - Private User Field Disclosure via Directory Items IDOR | Nuclei |
| CVE-2026-26341 | Tattile Camera < 1.181.5 - Default Login | Nuclei |
| CVE-2026-26980 | Ghost CMS Content API - SQL Injection | Nuclei |
| CVE-2026-27174 | MajorDoMo - Unauthenticated RCE | Nuclei |
| CVE-2026-27464 | Metabase CVE-2026-27464 notification template evaluation | Agent Asteroid |
| CVE-2026-27771 | Gitea CVE-2026-27771 POTENTIAL EXPOSURE | Agent Asteroid |
| CVE-2026-27833 | Piwigo < 16.3.0 - Unauthenticated Information Disclosure via History API | Nuclei |
| CVE-2026-27934 | Discourse < 2026.1.2/2026.2.1/2026.3.0-latest.1 - Unauthenticated Private User Action Disclosure | Nuclei |
| CVE-2026-27960 | OpenCTI < 6.9.13 - Authentication Bypass via User Impersonation | Nuclei |
| CVE-2026-27971 | Qwik - Unauthenticated RCE via server$ Deserialization | Nuclei |
| CVE-2026-28141 | NextGEN Gallery <= 4.2.3 - Reflected Cross-Site Scripting | Nuclei |
| CVE-2026-28411 | WeGIA < 3.6.5 - Unauthenticated Authentication Bypass via extract() | Nuclei |
| CVE-2026-28414 | Gradio - Absolute Path Traversal | Nuclei |
| CVE-2026-29059 | Windmill/Nextcloud Flow < 1.603.3 - Unauthenticated Path Traversal | Nuclei |
| CVE-2026-29962 | HSC MailInspector - Local File Inclusion | Nuclei |
| CVE-2026-29963 | HSC MailInspector - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2026-30824 | Flowise - NVIDIA NIM Endpoints Missing Authentication | Nuclei |
| CVE-2026-30849 | MantisBT < 2.28.1 - SOAP API Authentication Bypass | Nuclei |
| CVE-2026-30928 | Glances - Information Disclosure | Nuclei |
| CVE-2026-30958 | OneUptime < 10.0.21 - Path Traversal | Nuclei |
| CVE-2026-31831 | Tautulli <= 2.16.1 - Path Traversal | Nuclei |
| CVE-2026-32596 | Glances - Information Disclosure | Nuclei |
| CVE-2026-32710 | MariaDB JSON_SCHEMA_VALID memory corruption | Agent Asteroid |
| CVE-2026-33017 | Langflow Code Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-33032 | Nginx UI - Broken Access Control | Nuclei |
| CVE-2026-33057 | Mesop AI Sandbox <= 1.2.2 - Remote Code Execution | Nuclei |
| CVE-2026-33340 | LoLLMs WEBUI - Server-Side Request Forgery | Nuclei |
| CVE-2026-33466 | Logstash GeoIP CVE-2026-33466 (advertised release) | Agent Asteroid |
| CVE-2026-33476 | SiYuan <= v3.6.1 - Path Traversal | Nuclei |
| CVE-2026-33497 | Langflow < 1.7.0 - Path Traversal | Nuclei |
| CVE-2026-33626 | LMDeploy - Server-Side Request Forgery | Nuclei |
| CVE-2026-33725 | Metabase CVE-2026-33725 Enterprise serialization import code execution | Agent Asteroid |
| CVE-2026-34151 | XWiki Platform - Path Traversal | Nuclei |
| CVE-2026-34156 | NocoBase CVE-2026-34156 workflow sandbox escape | Agent Asteroid |
| CVE-2026-34197 | Apache ActiveMQ Improper Input Validation Vulnerability | Nuclei |
| CVE-2026-34453 | SiYuan <= v3.6.1 - Bookmark Data Disclosure | Nuclei |
| CVE-2026-34486 | Apache Tomcat Missing Encryption of Sensitive Data Vulnerability | Nuclei |
| CVE-2026-34908 | Ubiquiti UniFi OS Improper Access Control Vulnerability | Nuclei |
| CVE-2026-34910 | Ubiquiti UniFi OS Improper Input Validation Vulnerability | Nuclei |
| CVE-2026-34976 | Dgraph CVE-2026-34976 restoreTenant authorization bypass | Agent Asteroid |
| CVE-2026-35037 | Ech0 < 4.2.8 - Server-Side Request Forgery | Nuclei |
| CVE-2026-35273 | Oracle PeopleSoft Enterprise PeopleTools Missing Authentication for Critical Function Vulnerability | Nuclei |
| CVE-2026-35616 | Fortinet FortiClient EMS Improper Access Control Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-39339 | ChurchCRM - API Authentication Bypass via URL Injection | Nuclei |
| CVE-2026-39364 | Vite Dev Server - Directory Traversal | Nuclei |
| CVE-2026-39468 | Meta Box – WordPress Custom Fields Framework (CVE-2026-39468) | Agent Asteroid |
| CVE-2026-39987 | Marimo Remote Code Execution Vulnerability | Nuclei |
| CVE-2026-40242 | Arcane <= 1.17.2 - Server-Side Request Forgery | Nuclei |
| CVE-2026-40281 | Gotenberg CVE-2026-40281 ExifTool argument injection | Agent Asteroid |
| CVE-2026-40887 | Vendure Core - SQL Injection | Nuclei |
| CVE-2026-41179 | RClone RC - Command Injection | Nuclei |
| CVE-2026-41452 | Krayin CRM < 2.2.1 - Installer Authentication Bypass | Nuclei |
| CVE-2026-41492 | Dgraph CVE-2026-41492 admin token disclosure | Agent Asteroid |
| CVE-2026-41940 | WebPros cPanel & WHM and WP2 (WordPress Squared) Missing Authentication for Critical Function Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-41948 | Dify <=1.14.1 - Unauthenticated Plugin Daemon Path Traversal | Nuclei |
| CVE-2026-42018 | JFrog Artifactory Improper Authentication Vulnerability | Nuclei |
| CVE-2026-42031 | CKAN DataStore SQL Search - SQL Injection | Nuclei |
| CVE-2026-42208 | BerriAI LiteLLM SQL Injection Vulnerability | Nuclei |
| CVE-2026-42271 | BerriAI LiteLLM Command Injection Vulnerability | Nuclei |
| CVE-2026-42281 | MagicMirror <= 2.35.0 - Server-Side Request Forgery | Nuclei |
| CVE-2026-42461 | Arcane < 1.18.0 - Unauthenticated Template and Env Disclosure | Nuclei |
| CVE-2026-42564 | jotty.page < 1.22.0 - Path Traversal | Nuclei |
| CVE-2026-42569 | phpVMS < 7.0.6 - Legacy Importer Authorization Bypass | Nuclei |
| CVE-2026-42589 | Gotenberg CVE-2026-42589 ExifTool metadata-key injection | Agent Asteroid |
| CVE-2026-42647 | JoomSport (CVE-2026-42647) | Agent Asteroid |
| CVE-2026-42796 | Arelle CVE-2026-42796 remote plugin loading | Agent Asteroid |
| CVE-2026-44262 | Scramble Laravel - Remote Code Execution | Nuclei |
| CVE-2026-44338 | PraisonAI - Authentication Bypass | Nuclei |
| CVE-2026-44343 | WGDashboard < 4.3.2 - Unauthenticated File Read | Nuclei |
| CVE-2026-44825 | Apache Solr 9.4.0-9.10.1 / 10.0.0 - Hardcoded Default Credentials | Nuclei |
| CVE-2026-45298 | Dozzle - Server Side Request Forgery | Nuclei |
| CVE-2026-45695 | Kopia CVE-2026-45695 SSH command injection | Agent Asteroid |
| CVE-2026-46339 | 9Router CVE-2026-46339 MCP command execution | Agent Asteroid |
| CVE-2026-46364 | phpMyFAQ <= 4.1.1 - SQL Injection | Nuclei |
| CVE-2026-46372 | SillyTavern - Server-Side Request Forgery | Nuclei |
| CVE-2026-46442 | Flowise CVE-2026-46442 authenticated Custom Function RCE | Agent Asteroid |
| CVE-2026-46725 | TYPO3 ceselector Extension - Insecure Deserialization | Nuclei |
| CVE-2026-47717 | FUXA 1.3.0 - Unauthenticated ICS/SCADA Project Data Disclosure | Nuclei |
| CVE-2026-48048 | XWiki Platform - Password Hash Disclosure | Nuclei |
| CVE-2026-48558 | SimpleHelp Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2026-48611 | phpBB < 3.3.17 - Authentication Bypass | Nuclei |
| CVE-2026-48710 | Kludex Starlette HTTP Request/Response Smuggling Vulnerability | Nuclei |
| CVE-2026-49060 | Hippoo Mobile App for WooCommerce - Broken Access Control | Nuclei |
| CVE-2026-49069 | WPZOOM Portfolio <= 1.4.21 - Reflected Cross-Site Scripting | Nuclei |
| CVE-2026-49772 | The Events Calendar (CVE-2026-49772) | Agent Asteroid |
| CVE-2026-49777 | WordPress Product Slider Pro for WooCommerce < 3.5.4 - Supply Chain Backdoor RCE | Nuclei |
| CVE-2026-49869 | Kestra OSS OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2026-50751 | Check Point Security Gateway Improper Authentication Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-52715 | GEO my WordPress (CVE-2026-52715) | Agent Asteroid |
| CVE-2026-52806 | Gogs <= 0.14.2 - Authenticated RCE via git rebase Argument Injection | Nuclei |
| CVE-2026-52824 | Kimai <= 2.57.0 - Default APP_SECRET Authentication Bypass | Nuclei |
| CVE-2026-53519 | Nezha Dashboard < 2.0.13 - Path Traversal | Nuclei |
| CVE-2026-53576 | Kestra OSS CVE-2026-53576 authentication bypass/RCE | Agent Asteroid |
| CVE-2026-53595 | FreeScout < 1.8.224 - Invite Hash Authorization Bypass | Nuclei |
| CVE-2026-53753 | Crawl4AI CVE-2026-53753 computed-field sandbox escape | Agent Asteroid |
| CVE-2026-53755 | crawl4ai < 0.8.9 - Server Side Request Forgery | Nuclei |
| CVE-2026-53976 | OpenChamber <1.13.0 - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2026-54066 | SiYuan <= 3.6.5 - Unauthenticated Path Traversal | Nuclei |
| CVE-2026-54069 | SiYuan CVE-2026-54069 extension-origin authentication bypass | Agent Asteroid |
| CVE-2026-54419 | PIAF-HMS ec.php - SQL Injection | Nuclei |
| CVE-2026-54617 | GravitLauncher LaunchServer <=5.7.11 - Unauthenticated Path Traversal to Arbitrary File Read | Nuclei |
| CVE-2026-54836 | YMC Filter / Filter & Grids (CVE-2026-54836) | Agent Asteroid |
| CVE-2026-55040 | Microsoft SharePoint Weak Authentication Vulnerability | Nuclei |
| CVE-2026-55450 | Langflow CVE-2026-55450 unauthenticated upload | Agent Asteroid |
| CVE-2026-55552 | Yamcs <=5.11.12 - Arbitrary File Read | Nuclei |
| CVE-2026-55864 | GeoNetwork - Server-Side Request Forgery (SSRF) | Nuclei |
| CVE-2026-56062 | Quotes llama <= 3.1.5 - SQL Injection | Nuclei |
| CVE-2026-56070 | Advance Product Search <= 1.4.4 - Unauthenticated Time-Based Blind SQL Injection | Nuclei |
| CVE-2026-56265 | Crawl4AI CVE-2026-56265 default JWT signing key | Agent Asteroid |
| CVE-2026-56270 | Flowise <= 3.0.13 - Unauthenticated OAuth Configuration Disclosure | Nuclei |
| CVE-2026-56292 | AcyMailing < 10.11.1 - Unauthenticated SQL Injection | Nuclei |
| CVE-2026-56681 | 9router <=0.5.4 - Authentication Bypass | Nuclei |
| CVE-2026-56782 | Gorse < 0.5.10 - Unauthenticated Database Dump | Nuclei |
| CVE-2026-57219 | RabbitMQ Management - OAuth 2 Client Secret Disclosure | Nuclei |
| CVE-2026-57582 | GeoNetwork - Reflected Cross-Site Scripting | Nuclei |
| CVE-2026-58138 | Conductor CVE-2026-58138 script evaluation | Agent Asteroid |
| CVE-2026-58467 | Cockpit CMS <= 2.14.0 - Path Traversal / Local File Inclusion | Nuclei |
| CVE-2026-58644 | Microsoft SharePoint Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2026-59309 | vCenter CVE-2026-59309 POTENTIAL EXPOSURE | Agent Asteroid |
| CVE-2026-59310 | Broadcom VMware vCenter Path Traversal Vulnerability | Agent Asteroid |
| CVE-2026-59509 | cve-search 4.0-6.0.0 - Unauthenticated NoSQL Injection | Nuclei |
| CVE-2026-59726 | ruflo MCP Bridge - Unauthenticated RCE via terminal_execute | Nuclei |
| CVE-2026-59774 | Gitea CVE-2026-59774 POTENTIAL EXPOSURE | Agent Asteroid |
| CVE-2026-59822 | BerriAI LiteLLM Improper Authentication Vulnerability | Agent Asteroid |
| CVE-2026-59826 | Metabase CVE-2026-59826 H2 database creation code execution | Agent Asteroid |
| CVE-2026-59827 | Metabase CVE-2026-59827 H2 query-result deserialization | Agent Asteroid |
| CVE-2026-60004 | Gitea Code Injection Vulnerability | Agent Asteroid |
| CVE-2026-61560 | GitLab MCP Server < 2.1.27 - Unauthenticated SSE Transport Access | Nuclei |
| CVE-2026-61736 | LightRAG <= 1.5.3 - Credentialed CORS Wildcard | Nuclei |
| CVE-2026-61808 | LightRAG <= 1.5.4 - Missing Authentication | Nuclei |
| CVE-2026-63030 | WordPress Core Interpretation Conflict Vulnerability | Nuclei |
| CVE-2026-63077 | JetBrains TeamCity Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2026-64638 | WordPress Core < 7.0.3 - Preauth Reflected XSS (XSS2Shell) | Nuclei |
| CVE-2026-64849 | MLflow Server-Side Request Forgery Vulnerability | Agent Asteroid |
| CVE-2026-65442 | FormCraft3 <= 3.9.15 - Server-Side Request Forgery | Nuclei |
| CVE-2026-65555 | Uncanny Toolkit for LearnDash (CVE-2026-65555) | Agent Asteroid |
| CVE-2026-65694 | Microweber CMS <= 2.0.20 - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2026-65761 | Joomla Easy Store - SQL Injection | Nuclei |
| CVE-2026-65906 | TeamCity CVE-2026-65906 (advertised release) | Agent Asteroid |
| CVE-2026-65907 | TeamCity CVE-2026-65907 (advertised release) | Agent Asteroid |
| CVE-2026-65919 | Meshery <1.0.57 - Arbitrary File Read | Nuclei |
| CVE-2026-66914 | SEBLOD for Joomla < 3.30.0/< 4.7.0/< 6.0.1 - Path Traversal | Nuclei |
| CVE-2026-67208 | Juggle <= 1.6.0 - Unauthenticated Exposed H2 Database Console | Nuclei |
| CVE-2026-69084 | SiYuan CVE-2026-69084 publish-mode SQL execution | Agent Asteroid |
| CVE-2026-69085 | SiYuan CVE-2026-69085 searchDocs SQL injection | Agent Asteroid |
| CVE-2026-69251 | Flowise CVE-2026-69251 TypeORM RCE | Agent Asteroid |
| CVE-2026-71209 | Audiobookshelf - Authentication Bypass | Nuclei |
| CVE-2026-71495 | Wanderer unauthenticated server-side request forgery (CVE-2026-71495) | Agent Asteroid |
| CVE-2026-72898 | Metabase SQL Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-72899 | Metabase CVE-2026-72899 public-link field-filter SQL injection | Agent Asteroid |
| CVE-2026-72900 | Metabase CVE-2026-72900 audit database authorization bypass | Agent Asteroid |
| CVE-2026-73570 | Zimbra Collaboration Suite (ZCS) OS Command Injection Vulnerability | Nuclei |
| CVE-2026-73577 | Apache OFBiz CVE-2026-73577 unauthenticated path-suffix view authorization bypass | Agent Asteroid |
| CVE-2026-75128 | Langchain-Chatchat <= 0.3.1.3 - Unauthenticated RCE | Nuclei |
| CVE-2026-76268 | Splunk Enterprise Patroni REST API - Missing Authentication RCE | Nuclei |
| CVE-2026-76460 | Cisco Identity Services Engine Incorrect Use of Privileged APIs Vulnerability | Nuclei |
| CVE-2026-76904 | GeoServer jsonArrayContains CQL Filter - SQL Injection | Nuclei |
| CVE-2026-77806 | SPIP < 4.4.22 - Unauthenticated RCE | Nuclei |
| CVE-2026-79844 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79845 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79846 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79847 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79848 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79849 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79850 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79851 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79852 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79853 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79854 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79855 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79856 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79857 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79858 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79859 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79860 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79861 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79862 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79863 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79864 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79865 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79866 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79867 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79868 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79869 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79870 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79871 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79872 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79873 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79874 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79875 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-79876 | HPE AOS HPESBNW05162 | Agent Asteroid |
| CVE-2026-80099 | Newfold WordPress Plugins - Unauthenticated Admin Bypass via Empty HMAC Secret | Nuclei |
| CVE-2026-80462 | Chef Automate API Gateway - Authentication Bypass | Nuclei |
| CVE-2026-81578 | PaperCut NG/MF Missing Authentication for Critical Function Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-82078 | PaperCut NG/MF Unsafe Reflection Vulnerability | Agent Asteroid |
| CVE-2026-82329 | JFrog Artifactory Improper Authentication Vulnerability | Nuclei |
| CVE-2026-82456 | argocd-mcp 0.8.0 - Unauthenticated MCP Session and Tool Access | Nuclei |
| CVE-2026-83548 | SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability | Nuclei |
| CVE-2026-85200 | GEO my WP <=4.5.5.3 - Unauthenticated Local File Inclusion | Nuclei |
| CVE-2026-85595 | Traefik CVE-2026-85595 digestAuth bypass | Agent Asteroid |
| CVE-2026-85688 | TEN Framework - Arbitrary File Read & Write | Nuclei |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition Path Traversal Vulnerability | Nuclei |
| CVE-2026-85714 | Stirling-PDF CVE-2026-85714 H2 import RCE | Agent Asteroid |
| CVE-2026-86206 | N-able N-central - Access Control Bypass via Path Confusion and Forwarded Header Spoofing | Nuclei |
| CVE-2026-86207 | N-able N-central - Authentication Bypass | Nuclei |
| CVE-2026-86218 | N-able N-central Static Code Injection Vulnerability | Nuclei |
| CVE-2026-87902 | WordPress Core Remote File Inclusion Vulnerability | Nuclei |
| CVE-2026-88771 | Citrix NetScaler Improper Input Validation Vulnerability | Agent Asteroid |
| CVE-2026-88772 | Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability | Agent Asteroid |
| CVE-2026-89013 | Dolibarr < 24.0.0 - Authorization Bypass via hashp Parameter | Nuclei |
| CVE-2026-89026 | Issabel Framework - Hard-Coded PBX API JWT Key | Nuclei |
| CVE-2026-90436 | Apache Axis 1.x CVE-2026-90436 unauthenticated SOAP fault class-loading RCE | Agent Asteroid |
| CVE-2026-91136 | Divi Plus <= 2.4.0 - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2026-93616 | Check Point Multiple Products Path Traversal Vulnerability | Nuclei |
| CVE-2026-93674 | Langflow CVE-2026-93674 import-validation RCE | Agent Asteroid |
| CVE-2026-94169 | The Grid <= 2.8.1 - Unauthenticated Code Injection | Nuclei |
| CVE-2026-96652 | Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | Agent Asteroid |
| CVE-2026-96654 | Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability | Agent Asteroid |
| CVE-2026-96655 | Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | Agent Asteroid |
| CVE-2026-96656 | Plex Media Server External Control of File Name or Path Vulnerability | Agent Asteroid |
| CVE-2026-100109 | Security For WooCommerce (CVE-2026-100109) | Agent Asteroid |
| CVE-2026-102610 | fast-agent MCP server unauthenticated remote agent access (CVE-2026-102610) | Agent Asteroid |
| CVE-2026-102764 | BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability | Nuclei |
| CVE-2026-102782 | OrdaSoft Simple Membership < 7.4.0 - SQL Injection | Nuclei |
| CVE-2026-102878 | mcp-chrome-bridge (hangwin/mcp-chrome) <= 1.0.31 - CORS Origin Bypass (CSWSH) | Nuclei |
| CVE-2026-102894 | GPUStack CVE-2026-102894 unauthenticated SAML callback account takeover | Agent Asteroid |
| CVE-2026-102895 | GPUStack CVE-2026-102895 unauthenticated administrator bypass | Agent Asteroid |
| CVE-2026-103956 | Loom CVE-2026-103956 authentication bypass | Agent Asteroid |
| CVE-2026-104203 | Traccar CVE-2026-104203 media authentication bypass via semicolon path parameter | Agent Asteroid |
| CVE-2026-104608 | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Agent Asteroid |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | Agent Asteroid |
| CVE-2026-105133 | Ahsay AhsayCBS Improper Authentication Vulnerability | Nuclei |
| CVE-2026-105740 | Langflow CVE-2026-105740 authenticated MCP RCE | Agent Asteroid |
| CVE-2026-107861 | Kiloview E3 October 2026 critical command injection | Agent Asteroid |
| CVE-2026-108123 | WP Booking System <= 2.1.0.3 - Unauthenticated Email Log Disclosure | Nuclei |
| CVE-2026-109122 | Kiloview E3 October 2026 critical command injection | Agent Asteroid |
| CVE-2026-109618 | PHP Memory Corruption Vulnerability | Agent Asteroid |
| CVE-2026-109619 | PHP Stale Internal Request-State Vulnerability | Agent Asteroid |
| CVE-2026-110243 | Kiloview E3 October 2026 critical command injection | Agent Asteroid |
| CVE-2026-110288 | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Agent Asteroid |
| CVE-2026-110447 | Collabora Online – Built-in CODE Server OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2026-111497 | Google Brotli Unchecked Return Value Vulnerability | Agent Asteroid |
| CVE-2026-112866 | Product Filter by WBW <= 3.4.6 - SQL Injection | Nuclei |
| CVE-2026-114612 | LiteLLM CVE-2026-114612 | Agent Asteroid |
| CVE-2026-115547 | Okta Access Gateway CVE-2026-115547 | Agent Asteroid |
| CVE-2026-116167 | SiYuan 2.9.0-3.8.6 - Unauthenticated XSS via check-auth "to" Parameter | Nuclei |
| CVE-2026-116485 | danmu_api - Unauthenticated Access to Admin API via Default Token | Nuclei |
| CVE-2026-118623 | MLflow CVE-2026-118623 pickle evaluation artifact deserialization RCE | Agent Asteroid |
| CVE-2026-118627 | MLflow CVE-2026-118627 SHAP explainer deserialization RCE | Agent Asteroid |
| CVE-2026-118628 | MLflow CVE-2026-118628 get-artifacts SSRF information disclosure | Agent Asteroid |
| CVE-2026-119481 | JetFormBuilder (CVE-2026-119481) | Agent Asteroid |
| CVE-2026-119923 | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Agent Asteroid |
| CVE-2026-119924 | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Agent Asteroid |
| CVE-2026-119977 | WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability | Nuclei + Agent Asteroid |
| CVE-2026-120446 | madong-admin-saas <= 5.1.4 - Unauthenticated Platform Tenant Management Access | Nuclei |
| CVE-2026-120656 | OpenKruise unauthenticated pprof debug endpoint exposed (CVE-2026-120656) | Agent Asteroid |
| CVE-2026-123158 | OpenSSH Password Authentication Bypass on musl libc (CVE-2026-123158, 'sshole') | Agent Asteroid |
| CVE-2026-123201 | bukuserver unauthenticated server-side request forgery (CVE-2026-123201) | Agent Asteroid |

</details>

<details><summary><b>2025 — 132 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2025-0108 | Palo Alto Networks PAN-OS Authentication Bypass Vulnerability | Nuclei |
| CVE-2025-0282 | Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2025-0674 | Elber ESE DVB-S/S2 Authentication Bypass | Agent Asteroid |
| CVE-2025-0890 | Zyxel VMG4325-B10A Default Credentials Leading to RCE | Agent Asteroid |
| CVE-2025-1361 | IP2Location Country Blocker < 2.38.9 - Unauthenticated Information Disclosure | Nuclei |
| CVE-2025-1974 | Ingress-Nginx Controller - Remote Code Execution | Nuclei |
| CVE-2025-2221 | WordPress WPCOM Member <= 1.7.6 - SQL Injection | Nuclei |
| CVE-2025-2505 | Age Gate (CVE-2025-2505) | Agent Asteroid |
| CVE-2025-2558 | WordPress The Wound Theme <= 0.0.1 - Local File Inclusion | Nuclei |
| CVE-2025-2611 | ICTBroadcast - Command Injection | Nuclei |
| CVE-2025-2636 | > | Nuclei |
| CVE-2025-2746 | Kentico Xperience CMS Authentication Bypass Using an Alternate Path or Channel Vulnerability | Nuclei |
| CVE-2025-2747 | Kentico Xperience CMS Authentication Bypass Using an Alternate Path or Channel Vulnerability | Nuclei |
| CVE-2025-2775 | SysAid On-Prem Improper Restriction of XML External Entity Reference Vulnerability | Nuclei |
| CVE-2025-2776 | SysAid On-Prem Improper Restriction of XML External Entity Reference Vulnerability | Nuclei |
| CVE-2025-3248 | Langflow Missing Authentication Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-4008 | Smartbedded Meteobridge Command Injection Vulnerability | Nuclei |
| CVE-2025-4210 | Casdoor - Authorization Bypass | Nuclei |
| CVE-2025-4322 | Motors Theme <= 5.6.67 - Unauthenticated Privilege Escalation via Password Update/Account Takeover | Agent Asteroid |
| CVE-2025-4427 | Ivanti Endpoint Manager Mobile (EPMM) Authentication Bypass Vulnerability | Nuclei |
| CVE-2025-4524 | WordPress Madara Theme < 2.2.2.1 - Local File Inclusion | Nuclei |
| CVE-2025-5086 | Dassault Systèmes DELMIA Apriso Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2025-5777 | Citrix NetScaler ADC and Gateway Out-of-Bounds Read Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-5947 | Service Finder Bookings - Authentication Bypass | Nuclei |
| CVE-2025-8110 | Gogs Path Traversal Vulnerability | Nuclei |
| CVE-2025-9209 | RestroPress – Online Food Ordering System (CVE-2025-9209) | Agent Asteroid |
| CVE-2025-10035 | Fortra GoAnywhere MFT Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2025-10090 | Jinher OA - SQL Injection | Nuclei |
| CVE-2025-10162 | WordPress OrderConvo <= 15.1 - Path Traversal | Nuclei |
| CVE-2025-11371 | Gladinet CentreStack and Triofox Files or Directories Accessible to External Parties Vulnerability | Nuclei |
| CVE-2025-11452 | Asgaros Forum < 3.2.0 - SQL Injection | Nuclei |
| CVE-2025-11693 | Export WP Page to Static HTML & PDF (CVE-2025-11693) | Agent Asteroid |
| CVE-2025-12480 | Gladinet Triofox Improper Access Control Vulnerability | Nuclei |
| CVE-2025-12536 | SureForms – Contact Form, Payment Form & Other Custom Form Builder (CVE-2025-12536) | Agent Asteroid |
| CVE-2025-12841 | Bookit (CVE-2025-12841) | Agent Asteroid |
| CVE-2025-13339 | Hippoo Mobile App for WooCommerce <= 1.7.1 - Unauthenticated Arbitrary File Read | Nuclei |
| CVE-2025-13342 | Frontend Admin by DynamiApps (CVE-2025-13342) | Agent Asteroid |
| CVE-2025-13390 | WP Directory Kit (CVE-2025-13390) | Agent Asteroid |
| CVE-2025-13773 | Print Invoice & Delivery Notes for WooCommerce (CVE-2025-13773) | Agent Asteroid |
| CVE-2025-13801 | Yoco Payments (CVE-2025-13801) | Agent Asteroid |
| CVE-2025-14124 | Team WordPress Plugin (TLP Team) <= 5.0.9 - SQL Injection | Nuclei |
| CVE-2025-14437 | WordPress Hummingbird <= 3.18.0 - Sensitive Information Exposure via Log File | Nuclei |
| CVE-2025-14611 | Gladinet CentreStack and Triofox Hard Coded Cryptographic Vulnerability | Nuclei |
| CVE-2025-14733 | WatchGuard Firebox Out of Bounds Write Vulnerability | Agent Asteroid |
| CVE-2025-14847 | MongoDB and MongoDB Server Improper Handling of Length Parameter Inconsistency Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-14998 | Branda (CVE-2025-14998) | Agent Asteroid |
| CVE-2025-15403 | RegistrationMagic (CVE-2025-15403) | Agent Asteroid |
| CVE-2025-20188 | Cisco IOS XE WLC - Arbitrary File Upload | Nuclei |
| CVE-2025-20281 | Cisco Identity Services Engine Injection Vulnerability | Nuclei |
| CVE-2025-20362 | Cisco Secure Firewall Adaptive Security (ASA) Appliance and Secure Firewall Threat Defense (FTD) Missing Authorization Vulnerability | Nuclei |
| CVE-2025-22457 | Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2025-23006 | SonicWall SMA1000 Appliances Deserialization Vulnerability | Agent Asteroid |
| CVE-2025-23016 | FastCGI Integer Overflow Leading to Heap Overflow (CVE-2025-23016) | Agent Asteroid |
| CVE-2025-23211 | Tandoor CVE-2025-23211 template injection | Agent Asteroid |
| CVE-2025-24893 | XWiki Platform Eval Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-25257 | Fortinet FortiWeb SQL Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-25570 | Vue Vben Admin - Default Credentials | Nuclei |
| CVE-2025-26399 | SolarWinds Web Help Desk Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2025-27364 | MITRE Caldera Agent Dynamic Compilation RCE | Agent Asteroid |
| CVE-2025-27636 | Apache Camel Exec Component Command Injection & Internal Method Invocation | Nuclei |
| CVE-2025-27817 | Apache Kafka Client - Arbitrary File Read | Nuclei |
| CVE-2025-27915 | Synacor Zimbra Collaboration Suite (ZCS) Cross-site Scripting Vulnerability | Nuclei |
| CVE-2025-28242 | DAEnetIP4 METO v1.25 - Session Hijacking | Nuclei |
| CVE-2025-28367 | mojoPortal <=2.9.0.1 - Directory Traversal | Nuclei |
| CVE-2025-29635 | D-Link DIR-823X Command Injection Vulnerability | Nuclei |
| CVE-2025-29891 | Apache Camel Exec Component Command Injection & Internal Method Invocation | Nuclei |
| CVE-2025-29927 | Next.js Middleware Bypass | Nuclei |
| CVE-2025-30406 | Gladinet CentreStack and Triofox Use of Hard-coded Cryptographic Key Vulnerability | Nuclei |
| CVE-2025-31125 | Vite Vitejs Improper Access Control Vulnerability | Nuclei |
| CVE-2025-31161 | CrushFTP Authentication Bypass Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-31324 | SAP NetWeaver Unrestricted File Upload Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-32101 | UNA CMS <= 14.0.0-RC4 - PHP Object Injection (Verified RCE) | Nuclei |
| CVE-2025-32432 | Craft CMS Code Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-32433 | Erlang Erlang/OTP SSH Server Missing Authentication for Critical Function Vulnerability | Agent Asteroid |
| CVE-2025-32756 | Fortinet Multiple Products Stack-Based Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2025-32778 | Web-Check < 2.0.1 Screenshot API - OS Command Injection | Nuclei |
| CVE-2025-32966 | DataEase CVE-2025-32966 JDBC code execution | Agent Asteroid |
| CVE-2025-34026 | Versa Concerto Improper Authentication Vulnerability | Nuclei |
| CVE-2025-34028 | Commvault Command Center Path Traversal Vulnerability | Nuclei |
| CVE-2025-34030 | sar2html CVE-2025-34030 command injection | Agent Asteroid |
| CVE-2025-34033 | Blue Angel Software Suite (5V Technologies) - OS Command Injection | Nuclei |
| CVE-2025-34291 | Langflow Origin Validation Error Vulnerability | Nuclei |
| CVE-2025-37164 | Hewlett Packard Enterprise (HPE) OneView Code Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-40536 | SolarWinds Web Help Desk Security Control Bypass Vulnerability | Nuclei |
| CVE-2025-40551 | SolarWinds Web Help Desk Deserialization of Untrusted Data Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-40552 | SolarWinds Web Help Desk - Authentication Bypass | Nuclei |
| CVE-2025-40554 | SolarWinds Web Help Desk - Authentication Bypass | Nuclei |
| CVE-2025-47577 | TI WooCommerce Wishlist (CVE-2025-47577) | Agent Asteroid |
| CVE-2025-47812 | Wing FTP Server Improper Neutralization of Null Byte or NUL Character Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-48281 | MyStyle Custom Product Designer (CVE-2025-48281) | Agent Asteroid |
| CVE-2025-48827 | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Agent Asteroid |
| CVE-2025-48828 | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Agent Asteroid |
| CVE-2025-49001 | DataEase < 2.10.10 - JWT Authentication Bypass | Nuclei |
| CVE-2025-49706 | Microsoft SharePoint Improper Authentication Vulnerability | Nuclei |
| CVE-2025-52691 | SmarterTools SmarterMail Unrestricted Upload of File with Dangerous Type Vulnerability | Agent Asteroid |
| CVE-2025-52694 | Advantech WISE-IoTSuite/SaaS - SQL Injection | Nuclei |
| CVE-2025-53521 | F5 BIG-IP Stack-Based Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2025-53770 | Microsoft SharePoint Deserialization of Untrusted Data Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-54253 | Adobe Experience Manager Forms Code Execution Vulnerability | Agent Asteroid |
| CVE-2025-54309 |  CrushFTP Unprotected Alternate Channel Vulnerability | Agent Asteroid |
| CVE-2025-54726 | WordPress JS Archive List <= 6.1.5 - SQL Injection | Nuclei |
| CVE-2025-54988 | Apache Tika CVE-2025-54988 PDF/XFA XXE | Agent Asteroid |
| CVE-2025-55150 | Stirling-PDF CVE-2025-55150 HTML conversion SSRF | Agent Asteroid |
| CVE-2025-55182 | Meta React Server Components Remote Code Execution Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-56520 | Dify v1.6.0 - Server-Side Request Forgery | Nuclei |
| CVE-2025-57231 | Docmost 0.2.1-0.21.0 - Arbitrary File Read | Nuclei |
| CVE-2025-57819 | Sangoma FreePBX Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2025-58360 | OSGeo GeoServer Improper Restriction of XML External Entity Reference Vulnerability | Nuclei |
| CVE-2025-59287 | Microsoft Windows Server Update Service (WSUS) Deserialization of Untrusted Data Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-59341 | esm.sh <= v136 - Local File Inclusion | Nuclei |
| CVE-2025-59528 | Flowise CVE-2025-59528 CustomMCP RCE | Agent Asteroid |
| CVE-2025-59718 | Fortinet Multiple Products Improper Verification of Cryptographic Signature Vulnerability | Agent Asteroid |
| CVE-2025-61757 | Oracle Fusion Middleware Missing Authentication for Critical Function Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-61882 | Oracle E-Business Suite Unspecified Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-61884 | Oracle E-Business Suite Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2025-62168 | Squid CVE-2025-62168 authentication credential disclosure | Agent Asteroid |
| CVE-2025-62593 | Ray-Project Ray Code Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2025-64446 | Fortinet FortiWeb Path Traversal Vulnerability | Agent Asteroid |
| CVE-2025-64500 | Symfony HttpFoundation - Access Control Bypass via PATH_INFO | Nuclei |
| CVE-2025-66516 | Apache Tika - XML External Entity Injection | Nuclei |
| CVE-2025-66744 | Yonyou YonBIP - Path Traversal | Nuclei |
| CVE-2025-67303 | ComfyUI-Manager CVE-2025-67303 configuration integrity | Agent Asteroid |
| CVE-2025-68043 | LottieFiles WordPress Plugin <= 3.0.0 - Missing Authorization | Nuclei |
| CVE-2025-68461 | RoundCube Webmail Cross-site Scripting Vulnerability | Nuclei |
| CVE-2025-68493 | Apache Struts XWork - XML External Entity Injection | Nuclei |
| CVE-2025-68645 | Synacor Zimbra Collaboration Suite (ZCS) PHP Remote File Inclusion Vulnerability | Nuclei |
| CVE-2025-69411 | ionCube tester plus (CVE-2025-69411) | Agent Asteroid |
| CVE-2025-69971 | FUXA <= 1.2.7 - Hardcoded JWT Secret Authentication Bypass | Nuclei |
| CVE-2025-71243 | SPIP Saisies - Remote Code Execution | Nuclei |
| CVE-2025-71258 | BMC FootPrints 'searchWeb' - Server-Side Request Forgery | Nuclei |
| CVE-2025-71259 | BMC FootPrints 'feedUrl' - Server-Side Request Forgery | Nuclei |
| CVE-2025-71334 | Flowise CVE-2025-71334 storage path traversal | Agent Asteroid |

</details>

<details><summary><b>2024 — 174 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2024-0012 | Palo Alto Networks PAN-OS Management Interface Authentication Bypass Vulnerability | Nuclei |
| CVE-2024-0204 | Fortra GoAnywhere MFT - Authentication Bypass | Nuclei |
| CVE-2024-0692 | SolarWinds Security Event Manager unauthenticated remote code execution | Agent Asteroid |
| CVE-2024-1212 | Progress Kemp LoadMaster OS Command Injection Vulnerability | Nuclei |
| CVE-2024-1708 | ConnectWise ScreenConnect Path Traversal Vulnerability | Nuclei |
| CVE-2024-1709 | ConnectWise ScreenConnect Authentication Bypass Vulnerability | Nuclei |
| CVE-2024-1751 | Tutor LMS <= 2.1.10 - SQL Injection | Nuclei |
| CVE-2024-2194 | WP Statistics Unauthenticated Stored Cross-Site Scripting | Agent Asteroid |
| CVE-2024-2389 | Progress Kemp Flowmon - Command Injection | Nuclei |
| CVE-2024-2879 | LayerSlider 7.9.11 - 7.10.0 - Unauthenticated SQL Injection | Agent Asteroid |
| CVE-2024-3272 | D-Link Multiple NAS Devices Use of Hard-Coded Credentials Vulnerability | Nuclei |
| CVE-2024-3273 | D-Link Multiple NAS Devices Command Injection Vulnerability | Agent Asteroid |
| CVE-2024-3400 | Palo Alto Networks PAN-OS Command Injection Vulnerability | Nuclei |
| CVE-2024-3408 | D-Tale CVE-2024-3408 authentication bypass/RCE | Agent Asteroid |
| CVE-2024-4040 | CrushFTP VFS Sandbox Escape Vulnerability | Agent Asteroid |
| CVE-2024-4322 | LoLLMS WebUI < 9.8 - Path Traversal | Nuclei |
| CVE-2024-4358 | Progress Telerik Report Server Authentication Bypass by Spoofing Vulnerability | Nuclei |
| CVE-2024-4439 | Unauthenticated Stored Cross-Site Scripting Vulnerability in WordPress Core | Agent Asteroid |
| CVE-2024-4577 | PHP-CGI OS Command Injection Vulnerability | Nuclei |
| CVE-2024-4879 | ServiceNow Improper Input Validation Vulnerability | Nuclei |
| CVE-2024-4885 | Progress WhatsUp Gold Path Traversal Vulnerability | Nuclei |
| CVE-2024-4956 | Sonatype Nexus Repository Manager 3 - Local File Inclusion | Nuclei |
| CVE-2024-5057 | Easy Digital Downloads (CVE-2024-5057) | Agent Asteroid |
| CVE-2024-5217 | ServiceNow Incomplete List of Disallowed Inputs Vulnerability | Nuclei |
| CVE-2024-5315 | Dolibarr ERP-CRM 9.0.1 - SQL Injection | Agent Asteroid |
| CVE-2024-5333 | The Events Calendar (CVE-2024-5333) | Agent Asteroid |
| CVE-2024-5910 | Palo Alto Networks Expedition Missing Authentication Vulnerability | Nuclei |
| CVE-2024-5932 | GiveWP – Donation Plugin and Fundraising Platform <= 3.14.1 - Unauthenticated PHP Object Injection to Remote Code Execution | Nuclei |
| CVE-2024-6235 | NetScaler Console - Sensitive Information Disclosure | Nuclei |
| CVE-2024-6250 | LOLLMS WebUI - Absolute Path Traversal | Nuclei |
| CVE-2024-6385 | GitLab Authentication Bypass Vulnerability. | Agent Asteroid |
| CVE-2024-6386 | WPML Multilingual CMS Authenticated Contributor+ Remote Code Execution (RCE) via Twig Server-Side Template Injection (SSTI) | Agent Asteroid |
| CVE-2024-6387 | OpenSSH Remote Code Execution Vulnerability | Agent Asteroid |
| CVE-2024-6633 | Default Credentials in Fortra FileCatalyst Workflow HSQLDB | Agent Asteroid |
| CVE-2024-6670 | Progress WhatsUp Gold SQL Injection Vulnerability | Nuclei |
| CVE-2024-6745 | SQL Injection in Simple Ticket Booking | Agent Asteroid |
| CVE-2024-6782 | Calibre <= 7.14.0 Remote Code Execution | Nuclei |
| CVE-2024-7029 | AVTECH IP camera Devices Command Injection Vulnerability | Agent Asteroid |
| CVE-2024-7120 | Command Injection in RAISECOM Gateway Devices | Agent Asteroid |
| CVE-2024-7589 | OpenSSH Pre-Authentication Async Signal Safety Issue | Agent Asteroid |
| CVE-2024-7593 | Ivanti Virtual Traffic Manager Authentication Bypass Vulnerability | Nuclei |
| CVE-2024-8522 | Unauthenticated SQL Injection Vulnerability in LearnPress Plugin | Agent Asteroid |
| CVE-2024-8672 | Widget Options Plugin <= 4.0.7 - Authenticated Remote Code Execution | Agent Asteroid |
| CVE-2024-8956 | PTZOptics PT30X-SDI/NDI Cameras Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2024-8957 | PTZOptics PT30X-SDI/NDI Cameras OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2024-8963 | Ivanti Cloud Services Appliance (CSA) Path Traversal Vulnerability | Nuclei |
| CVE-2024-9164 | Gitlab Run pipelines on arbitrary branches. | Agent Asteroid |
| CVE-2024-9362 | Polyaxon - Unauthenticated Directory Traversal | Nuclei |
| CVE-2024-9463 | Palo Alto Networks Expedition OS Command Injection Vulnerability | Nuclei |
| CVE-2024-9465 | Palo Alto Networks Expedition SQL Injection Vulnerability | Nuclei |
| CVE-2024-9487 | GITHUB ENTERPRISE SERVER AUTHENTICATION BYPASS | Agent Asteroid |
| CVE-2024-9634 | PHP Object Injection Vulnerability in GiveWP Plugin | Agent Asteroid |
| CVE-2024-9643 | Four-Faith F3x36 - Authentication Bypass | Nuclei |
| CVE-2024-10542 | CleanTalk Plugin Arbitrary Plugin Installation (Via Reverse DNS Spoofing) | Agent Asteroid |
| CVE-2024-10763 | WordPress Campress Theme <= 1.35 - Unauthenticated Local File Inclusion | Nuclei |
| CVE-2024-10781 | CleanTalk Unauthorized Arbitrary Plugin Installation | Agent Asteroid |
| CVE-2024-10905 | SailPoint IdentityIQ Static File Exposure | Agent Asteroid |
| CVE-2024-10914 | D-Link NAS - Command Injection via Name Parameter | Nuclei |
| CVE-2024-10924 | Really Simple Security < 9.1.2 authentication bypass | Nuclei |
| CVE-2024-11205 | WPForms Lite Plugin 1.8.4 - 1.9.2.1 - Missing Authorization to Authenticated (Subscriber+) Payment Refund and Subscription Cancellation | Agent Asteroid |
| CVE-2024-11639 | Authentication Bypass in Ivanti CSA Admin Console | Agent Asteroid |
| CVE-2024-11667 | Zyxel Multiple Firewalls Path Traversal Vulnerability | Agent Asteroid |
| CVE-2024-11680 | ProjectSend Improper Authentication Vulnerability | Nuclei |
| CVE-2024-11972 | Hunk Companion Plugin Unauthenticated Arbitrary Plugin Installation | Agent Asteroid |
| CVE-2024-12025 | WordPress Collapsing Categories <= 3.0.8 - SQL Injection | Nuclei |
| CVE-2024-12084 | Rsync Heap Buffer Overflow | Agent Asteroid |
| CVE-2024-12209 | WP Umbrella Update Backup Restore & Monitoring <= 2.17.0 -  Local File Inclusion | Nuclei |
| CVE-2024-12987 | DrayTek Vigor Routers OS Command Injection Vulnerability | Nuclei |
| CVE-2024-13159 | Ivanti Endpoint Manager (EPM) Absolute Path Traversal Vulnerability | Nuclei |
| CVE-2024-13160 | Ivanti Endpoint Manager (EPM) Absolute Path Traversal Vulnerability | Nuclei |
| CVE-2024-13161 | Ivanti Endpoint Manager (EPM) Absolute Path Traversal Vulnerability | Nuclei |
| CVE-2024-20419 | Account Takeover in Cisco Smart Software Manager On-Prem | Agent Asteroid |
| CVE-2024-20439 | Cisco Smart Licensing Utility Static Credential Vulnerability | Nuclei |
| CVE-2024-20440 | Cisco Smart Licensing Utility UnAuthenticated Logs Exposure Leaking Plaintext Credentials | Nuclei |
| CVE-2024-20767 | Adobe ColdFusion Improper Access Control Vulnerability | Nuclei |
| CVE-2024-21287 | Oracle Agile Product Lifecycle Management (PLM) Incorrect Authorization Vulnerability | Agent Asteroid |
| CVE-2024-21733 | Apache Tomcat HTTP Request Smuggling (Client- Side Desync) | Agent Asteroid |
| CVE-2024-21762 | Fortinet FortiOS Out-of-Bound Write Vulnerability | Agent Asteroid |
| CVE-2024-21887 | Ivanti Connect Secure and Policy Secure Command Injection Vulnerability | Nuclei |
| CVE-2024-21893 | Ivanti Connect Secure, Policy Secure, and Neurons Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2024-22024 | Ivanti Connect Secure - XXE | Nuclei |
| CVE-2024-23113 | Fortinet Multiple Products Format String Vulnerability | Agent Asteroid |
| CVE-2024-23334 | AIOHTTP Path Traversal | Agent Asteroid |
| CVE-2024-23692 | Rejetto HTTP File Server Improper Neutralization of Special Elements Used in a Template Engine Vulnerability | Nuclei |
| CVE-2024-23897 | Jenkins Command Line Interface (CLI) Path Traversal Vulnerability | Nuclei |
| CVE-2024-23917 | JetBrains TeamCity > 2023.11.3 - Authentication Bypass | Nuclei |
| CVE-2024-24809 | Traccar - Unrestricted File Upload | Nuclei |
| CVE-2024-24882 | Masteriyo LMS (CVE-2024-24882) | Agent Asteroid |
| CVE-2024-24919 | Check Point Quantum Security Gateways Information Disclosure Vulnerability | Nuclei |
| CVE-2024-26291 | Avid NEXIS Agent - Arbitrary File Read | Nuclei |
| CVE-2024-26331 | ReCrystallize Server - Authentication Bypass | Nuclei |
| CVE-2024-27198 | JetBrains TeamCity Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2024-27199 | JetBrains TeamCity Relative Path Traversal Vulnerability | Nuclei |
| CVE-2024-27348 | Apache HugeGraph-Server Improper Access Control Vulnerability | Nuclei |
| CVE-2024-27443 | Synacor Zimbra Collaboration Suite (ZCS) Cross-Site Scripting (XSS) Vulnerability | Nuclei |
| CVE-2024-27497 | Linksys E2000 1.0.06 authentication bypass | Agent Asteroid |
| CVE-2024-27956 | WordPress Automatic Plugin <= 3.92.0 - SQL Injection | Nuclei |
| CVE-2024-28255 | OpenMetadata - Authentication Bypass | Nuclei |
| CVE-2024-28890 | Forminator plugin flaw in WordPress sites | Agent Asteroid |
| CVE-2024-28986 | SolarWinds Web Help Desk Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2024-28987 | SolarWinds Web Help Desk Hardcoded Credential Vulnerability | Nuclei |
| CVE-2024-28995 | SolarWinds Serv-U Path Traversal Vulnerability  | Nuclei |
| CVE-2024-29059 | Microsoft .NET Framework Information Disclosure Vulnerability | Nuclei |
| CVE-2024-29137 | WordPress Tourfic Plugin <= 2.11.7 - Cross-Site Scripting | Nuclei |
| CVE-2024-29269 | Telesquare TLR-2005KSH Unauthorized Remote Command Execution Vulnerability | Agent Asteroid |
| CVE-2024-29415 | Atlassian Confluence XSLT Macro - Server-Side Request Forgery | Nuclei |
| CVE-2024-29824 | Ivanti Endpoint Manager (EPM) SQL Injection Vulnerability | Nuclei |
| CVE-2024-29895 | Cacti cmd_realtime.php - Command Injection | Nuclei |
| CVE-2024-29973 | Zyxel NAS326 Firmware < V5.21(AAZF.17)C0 - Command Injection | Nuclei |
| CVE-2024-30502 | WP Travel Engine (CVE-2024-30502) | Agent Asteroid |
| CVE-2024-31849 | CData API Server < 23.4.8844 - Path Traversal | Nuclei |
| CVE-2024-31982 | XWiki < 4.10.20 - Remote code execution | Nuclei |
| CVE-2024-32114 | Apache ActiveMQ 6.x < 6.1.2 - Broken Access Control | Nuclei |
| CVE-2024-33544 | Unauthenticated SQL Injection Vulnerability in WZone Plugin | Agent Asteroid |
| CVE-2024-34102 | Adobe Commerce and Magento Open Source Improper Restriction of XML External Entity Reference (XXE) Vulnerability | Nuclei |
| CVE-2024-34470 | HSC MAILINSPECTOR PATH TRAVERSAL | Agent Asteroid |
| CVE-2024-35286 | Mitel MiCollab <= 9.8.0.33 - SQL Injection | Nuclei |
| CVE-2024-36401 | OSGeo GeoServer GeoTools Eval Injection Vulnerability | Nuclei |
| CVE-2024-36404 | GeoServer and GeoTools - Remote Code Execution | Nuclei |
| CVE-2024-36420 | Flowise 1.4.3 - Arbitrary File Read | Nuclei |
| CVE-2024-36991 | Splunk Enterprise - Local File Inclusion | Nuclei |
| CVE-2024-37014 | Langflow <= 1.0.12 - Remote Code Execution | Nuclei |
| CVE-2024-37032 | Ollama - Remote Code Execution | Nuclei |
| CVE-2024-37383 | RoundCube Webmail Cross-Site Scripting (XSS) Vulnerability | Agent Asteroid |
| CVE-2024-38077 | Windows Remote Desktop Licensing Service RCE | Agent Asteroid |
| CVE-2024-38475 | Apache HTTP Server Improper Escaping of Output Vulnerability | Nuclei |
| CVE-2024-38773 | FormLift for Infusionsoft Web Forms (CVE-2024-38773) | Agent Asteroid |
| CVE-2024-38812 | VMware vCenter Server Heap-Based Buffer Overflow Vulnerability | Nuclei |
| CVE-2024-38819 | WebMvc.fn/WebFlux.fn - Path Traversal | Nuclei |
| CVE-2024-38856 | Apache OFBiz Incorrect Authorization Vulnerability | Nuclei |
| CVE-2024-39717 | Versa Director Dangerous File Type Upload Vulnerability | Agent Asteroid |
| CVE-2024-40711 | Veeam Backup and Replication Deserialization Vulnerability | Agent Asteroid |
| CVE-2024-40725 | Source Code Disclosure in Apache HTTP Server | Agent Asteroid |
| CVE-2024-40766 | SonicWall SonicOS Improper Access Control Vulnerability | Agent Asteroid |
| CVE-2024-41713 | Mitel MiCollab Path Traversal Vulnerability | Nuclei |
| CVE-2024-42009 | RoundCube Webmail Cross-Site Scripting Vulnerability | Nuclei |
| CVE-2024-42450 | Versa Director Database exposure | Agent Asteroid |
| CVE-2024-42509 | Unauthenticated Command Injection Vulnerability in HPE Aruba Networking Access Points | Agent Asteroid |
| CVE-2024-43044 | JENKINS ARBITRARY FILE READ TO RCE | Agent Asteroid |
| CVE-2024-43144 | Cost Calculator Builder (CVE-2024-43144) | Agent Asteroid |
| CVE-2024-43399 | Mobile Security Framework (MobSF) Zip Slip | Agent Asteroid |
| CVE-2024-43919 | YARPP <= 5.30.10 - Missing Authorization | Nuclei |
| CVE-2024-45195 | Apache OFBiz Forced Browsing Vulnerability | Nuclei |
| CVE-2024-45409 | GitLab SAML Authentication Bypass Vulnerability. | Agent Asteroid |
| CVE-2024-45507 | Apache OFBiz - Remote Code Execution | Nuclei |
| CVE-2024-45519 | Synacor Zimbra Collaboration Suite (ZCS) Command Execution Vulnerability | Nuclei |
| CVE-2024-46938 | Sitecore Experience Platform <= 10.4 - Arbitrary File Read | Nuclei |
| CVE-2024-47176 | CUPS - Remote Code Execution | Nuclei |
| CVE-2024-47374 | Stored Cross-Site Scripting (XSS) Vulnerability in LiteSpeed Cache for WordPress | Agent Asteroid |
| CVE-2024-47533 | Cobbler XMLRPC Interface Authentication Bypass | Agent Asteroid |
| CVE-2024-47575 | Fortinet FortiManager Missing Authentication Vulnerability | Agent Asteroid |
| CVE-2024-48248 | NAKIVO Backup and Replication Absolute Path Traversal Vulnerability | Nuclei |
| CVE-2024-48259 | Cloudlog - SQL Injection | Nuclei |
| CVE-2024-49357 | ZimaOS <= v1.2.4 - Sensitive Information Disclosure | Nuclei |
| CVE-2024-50340 | Remote Access to Symfony Profiler via Injected Arguments | Nuclei |
| CVE-2024-50379 | Apache Tomcat Race Condition Remote Code Execution | Agent Asteroid |
| CVE-2024-50498 | WP Query Console <= 1.0 - Remote Code Execution | Nuclei |
| CVE-2024-50550 | LiteSpeed Cache Vulnerability Allowing privilege escalation | Agent Asteroid |
| CVE-2024-50603 | Aviatrix Controllers OS Command Injection Vulnerability | Nuclei |
| CVE-2024-50623 | Cleo Multiple Products Unrestricted File Upload Vulnerability | Nuclei + Agent Asteroid |
| CVE-2024-51378 | CyberPanel Incorrect Default Permissions Vulnerability | Agent Asteroid |
| CVE-2024-51479 | Next.js Authorization Bypass via Middleware | Agent Asteroid |
| CVE-2024-52875 | Kerio Control v9.2.5 - CRLF Injection | Nuclei |
| CVE-2024-53704 | SonicWall SonicOS SSLVPN Improper Authentication Vulnerability | Nuclei + Agent Asteroid |
| CVE-2024-54134 | MALICIOUS PACKAGES FOUND IN COMPROMISED @SOLANA/WEB3.JS LIBRARY | Agent Asteroid |
| CVE-2024-55550 | Mitel MiCollab Path Traversal Vulnerability | Nuclei |
| CVE-2024-55591 | Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2024-55956 | Cleo Multiple Products Unauthenticated File Upload Vulnerability | Agent Asteroid |
| CVE-2024-56145 | Craft CMS Code Injection Vulnerability | Nuclei |
| CVE-2024-56511 | DataEase < 2.10.4 - Authentication Bypass via Whitelist Path Traversal | Nuclei |
| CVE-2024-57726 | SimpleHelp Missing Authorization Vulnerability | Nuclei + Agent Asteroid |
| CVE-2024-57727 | SimpleHelp Path Traversal Vulnerability | Nuclei |
| CVE-2024-57728 | SimpleHelp Path Traversal Vulnerability | Nuclei |
| CVE-2024-58136 | Yiiframework Yii Improper Protection of Alternate Path Vulnerability | Nuclei |

</details>

<details><summary><b>2023 — 85 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2023-0669 | Fortra GoAnywhere MFT Remote Code Execution Vulnerability | Nuclei |
| CVE-2023-1389 | TP-Link Archer AX-21 Command Injection Vulnerability | Agent Asteroid |
| CVE-2023-1671 | Sophos Web Appliance Command Injection Vulnerability | Nuclei |
| CVE-2023-2356 | Mlflow <2.3.0 - Local File Inclusion | Nuclei |
| CVE-2023-2780 | Mlflow <2.3.1 - Local File Inclusion Bypass | Nuclei |
| CVE-2023-3452 | Canto (CVE-2023-3452) | Agent Asteroid |
| CVE-2023-3519 | Citrix NetScaler ADC and NetScaler Gateway Code Injection Vulnerability | Metasploit |
| CVE-2023-3643 | CAREL Boss Mini <= 1.4.0 - Local File Inclusion | Nuclei |
| CVE-2023-4966 | Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability | Nuclei |
| CVE-2023-5203 | WP Sessions Time Monitoring Full Automatic <= 1.0.8 - SQL Injection | Nuclei |
| CVE-2023-5204 | AI ChatBot (WPBot) (CVE-2023-5204) | Agent Asteroid |
| CVE-2023-6030 | LogDash Activity Log <= 1.1.3 - SQL Injection | Nuclei |
| CVE-2023-6553 | Wordpress Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution | Nuclei |
| CVE-2023-6750 | WordPress WP Clone <= 2.4.2 - Database Backup Exposure | Nuclei |
| CVE-2023-6825 | File Manager (free edition) (CVE-2023-6825) | Agent Asteroid |
| CVE-2023-7028 | GitLab Community and Enterprise Editions Improper Access Control Vulnerability | Nuclei |
| CVE-2023-7102 | Barracuda ESG Appliance Remote Code Execution | Nuclei |
| CVE-2023-7165 | JetBackup <= 2.0.9.7 - Sensitive Information Exposure via Directory Listing | Nuclei |
| CVE-2023-7337 | JS Help Desk <= 2.8.2 - SQL Injection | Nuclei |
| CVE-2023-20198 | Cisco IOS XE Web UI Privilege Escalation Vulnerability | Nuclei |
| CVE-2023-20273 | Cisco IOS XE Web UI Command Injection Vulnerability | Metasploit |
| CVE-2023-20887 | Vmware Aria Operations for Networks Command Injection Vulnerability | Nuclei |
| CVE-2023-21839 | Oracle WebLogic Server Unspecified Vulnerability | Metasploit |
| CVE-2023-22515 | Atlassian Confluence Data Center and Server Broken Access Control Vulnerability | Metasploit |
| CVE-2023-22518 | Atlassian Confluence Data Center and Server Improper Authorization Vulnerability | Agent Asteroid |
| CVE-2023-22527 | Atlassian Confluence Data Center and Server Template Injection Vulnerability | Nuclei |
| CVE-2023-23752 | Joomla! Improper Access Control Vulnerability | Nuclei |
| CVE-2023-24000 | GamiPress (CVE-2023-24000) | Agent Asteroid |
| CVE-2023-24489 | Citrix Content Collaboration ShareFile Improper Access Control Vulnerability | Nuclei |
| CVE-2023-25280 | D-Link DIR-820 Router OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2023-25717 | Multiple Ruckus Wireless Products CSRF and RCE Vulnerability | Nuclei |
| CVE-2023-25826 | OpenTSDB <= 2.4.1 - Unauthenticated RCE via Gnuplot Injection | Nuclei |
| CVE-2023-26359 | Adobe ColdFusion Deserialization of Untrusted Data Vulnerability | Custom check |
| CVE-2023-26360 | Adobe ColdFusion Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2023-27350 | PaperCut MF/NG Improper Access Control Vulnerability | Nuclei |
| CVE-2023-27524 | Apache Superset Insecure Default Initialization of Resource Vulnerability | Nuclei |
| CVE-2023-27997 | Fortinet FortiOS and FortiProxy SSL-VPN Heap-Based Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2023-28432 | MinIO Information Disclosure Vulnerability | Nuclei |
| CVE-2023-28461 | Array Networks AG and vxAG ArrayOS Missing Authentication for Critical Function Vulnerability | Agent Asteroid |
| CVE-2023-28787 | Quiz and Survey Master <= 8.1.4 - SQL Injection | Nuclei |
| CVE-2023-29298 | Adobe ColdFusion Improper Access Control Vulnerability | Nuclei |
| CVE-2023-29300 | Adobe ColdFusion Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2023-29357 | Microsoft SharePoint Server Privilege Escalation Vulnerability | Nuclei |
| CVE-2023-31719 | FUXA <= 1.1.12 - Unauthenticated SQL Injection | Nuclei |
| CVE-2023-32315 | Ignite Realtime Openfire Path Traversal Vulnerability | Nuclei |
| CVE-2023-33246 | Apache RocketMQ Command Execution Vulnerability | Nuclei |
| CVE-2023-34048 | VMware vCenter Server Out-of-Bounds Write Vulnerability | Nuclei |
| CVE-2023-34092 | Vite Dev Server - Information Exposure | Nuclei |
| CVE-2023-34362 | Progress MOVEit Transfer SQL Injection Vulnerability | Nuclei |
| CVE-2023-34990 | FortiWLM Directory Traversal | Agent Asteroid |
| CVE-2023-35078 | Ivanti Endpoint Manager Mobile Authentication Bypass Vulnerability | Nuclei |
| CVE-2023-35082 | Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core Authentication Bypass Vulnerability | Nuclei |
| CVE-2023-35708 | MOVEit Transfer - SQL Injection | Nuclei |
| CVE-2023-36845 | Juniper Junos OS EX Series and SRX Series PHP External Variable Modification Vulnerability | Agent Asteroid |
| CVE-2023-37580 | Synacor Zimbra Collaboration Suite (ZCS) Cross-Site Scripting (XSS) Vulnerability | Nuclei |
| CVE-2023-38035 | Ivanti Sentry Authentication Bypass Vulnerability | Nuclei |
| CVE-2023-38205 | Adobe ColdFusion Improper Access Control Vulnerability | Nuclei |
| CVE-2023-38646 | Known exploited vulnerability | Custom check |
| CVE-2023-38950 | ZKTeco BioTime Path Traversal Vulnerability | Nuclei |
| CVE-2023-40044 | Progress WS_FTP Server Deserialization of Untrusted Data Vulnerability | Metasploit |
| CVE-2023-40924 | SolarView Compact < 6.00 - Directory Traversal | Nuclei |
| CVE-2023-41265 | Qlik Sense HTTP Tunneling Vulnerability | Nuclei |
| CVE-2023-41266 | Qlik Sense Path Traversal Vulnerability | Nuclei |
| CVE-2023-42793 | JetBrains TeamCity Authentication Bypass Vulnerability | Tsunami + Nuclei |
| CVE-2023-43177 | CrushFTP < 10.5.1 - Unauthenticated Remote Code Execution | Nuclei |
| CVE-2023-43208 | NextGen Healthcare Mirth Connect Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2023-43770 | Roundcube Webmail Persistent Cross-Site Scripting (XSS) Vulnerability | Agent Asteroid |
| CVE-2023-45249 | Acronis Cyber Infrastructure (ACI) Insecure Default Password Vulnerability | Nuclei |
| CVE-2023-45727 | North Grid Proself Improper Restriction of XML External Entity (XXE) Reference Vulnerability | Agent Asteroid |
| CVE-2023-46604 | Apache ActiveMQ Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2023-46747 | F5 BIG-IP Configuration Utility Authentication Bypass Vulnerability | Nuclei |
| CVE-2023-46805 | Ivanti Connect Secure and Policy Secure Authentication Bypass Vulnerability | Nuclei |
| CVE-2023-47246 | SysAid Server Path Traversal Vulnerability | Nuclei |
| CVE-2023-47565 | QNAP VioStor NVR OS Command Injection Vulnerability | Nuclei |
| CVE-2023-48788 | Fortinet FortiClient EMS SQL Injection Vulnerability | Agent Asteroid |
| CVE-2023-49070 | Apache OFBiz < 18.12.10 - Arbitrary Code Execution | Nuclei |
| CVE-2023-49103 | ownCloud graphapi Information Disclosure Vulnerability | Nuclei |
| CVE-2023-49105 | ownCloud Improper Authentication Vulnerability | Agent Asteroid |
| CVE-2023-49897 | FXC AE1021, AE1021PE OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2023-50839 | JS Help Desk (CVE-2023-50839) | Agent Asteroid |
| CVE-2023-50969 | Imperva SecureSphere WAF Bypass for POST Data Inspection Rules | Agent Asteroid |
| CVE-2023-51467 | Apache OFBiz Authentication Bypass Vulnerability (CVE-2023-51467) | Nuclei |
| CVE-2023-52163 | Digiever DS-2105 Pro Missing Authorization Vulnerability | Nuclei |
| CVE-2023-52251 | Kafka UI 0.7.1 Command Injection | Nuclei |
| CVE-2023-54335 | eXtplorer <= 2.1.14 - Authentication Bypass | Nuclei |

</details>

<details><summary><b>2022 — 53 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2022-0412 | WordPress TI WooCommerce Wishlist <1.40.1 - SQL Injection | Nuclei |
| CVE-2022-0783 | Multiple Shipping Address Woocommerce < 2.0 - SQL Injection | Nuclei |
| CVE-2022-1040 | Sophos Firewall Authentication Bypass Vulnerability | Nuclei |
| CVE-2022-1281 | Photo Gallery WordPress v1.6.3 - SQL Injection | Nuclei |
| CVE-2022-1388 | F5 BIG-IP Missing Authentication Vulnerability | Tsunami + Nuclei |
| CVE-2022-1453 | RSVPMaker (CVE-2022-1453) | Agent Asteroid |
| CVE-2022-1692 | CP Image Store with Slideshow <= 1.0.67 - SQL Injection | Nuclei |
| CVE-2022-4223 | pgAdmin < 6.17 - Unauthenticated Remote Code Execution | Nuclei |
| CVE-2022-4940 | WCFM Membership <= 2.10.0 - Broken Access Control | Nuclei |
| CVE-2022-20699 | Cisco Small Business RV Series Routers Stack-based Buffer Overflow Vulnerability | Metasploit + Nuclei |
| CVE-2022-20821 | Cisco IOS XR Open Port Vulnerability | Nuclei |
| CVE-2022-21445 | Oracle ADF Faces Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2022-21587 | Oracle E-Business Suite Unspecified Vulnerability | Nuclei |
| CVE-2022-22536 | SAP Multiple Products HTTP Request Smuggling Vulnerability | Nuclei |
| CVE-2022-22947 | VMware Spring Cloud Gateway Code Injection Vulnerability | Tsunami + Nuclei |
| CVE-2022-22954 | VMware Workspace ONE Access and Identity Manager Server-Side Template Injection Vulnerability | Nuclei |
| CVE-2022-22963 | VMware Tanzu Spring Cloud Function Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2022-22965 | Spring Framework JDK 9+ Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2022-23131 | Zabbix Frontend Authentication Bypass Vulnerability | Nuclei |
| CVE-2022-23134 | Zabbix Frontend Improper Access Control Vulnerability | Nuclei |
| CVE-2022-24112 | Apache APISIX Authentication Bypass Vulnerability | Tsunami + Nuclei |
| CVE-2022-24706 | Apache CouchDB Insecure Default Initialization of Resource Vulnerability | Nuclei |
| CVE-2022-24816 | OSGeo GeoServer JAI-EXT Code Injection Vulnerability | Agent Asteroid |
| CVE-2022-24990 | TerraMaster OS Remote Command Execution Vulnerability | Nuclei |
| CVE-2022-26133 | Known exploited vulnerability | Custom check |
| CVE-2022-26134 | Atlassian Confluence Server and Data Center Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2022-26138 | Atlassian Questions For Confluence App Hard-coded Credentials Vulnerability | Nuclei |
| CVE-2022-26318 | WatchGuard Firebox and XTM Appliances Arbitrary Code Execution | Agent Asteroid |
| CVE-2022-26352 | dotCMS Unrestricted Upload of File Vulnerability | Nuclei |
| CVE-2022-27593 | QNAP Photo Station Externally Controlled Reference Vulnerability | Nuclei |
| CVE-2022-27926 | Synacor Zimbra Collaboration Suite (ZCS) Cross-Site Scripting (XSS) Vulnerability | Nuclei |
| CVE-2022-28810 | Zoho ManageEngine ADSelfService Plus Remote Code Execution Vulnerability | Metasploit |
| CVE-2022-29303 | SolarView Compact Command Injection Vulnerability | Nuclei |
| CVE-2022-29464 | WSO2 Multiple Products Unrestrictive Upload of File Vulnerability | Tsunami + Nuclei |
| CVE-2022-30525 | Zyxel Multiple Firewalls OS Command Injection Vulnerability | Nuclei |
| CVE-2022-31678 | VMWare Cloud Foundation NSX-V - XML External Entity (XXE) | Nuclei |
| CVE-2022-31814 | pfSense pfBlockerNG <=2.1..4_26 - OS Command Injection | Nuclei |
| CVE-2022-33891 | Apache Spark Command Injection Vulnerability | Nuclei |
| CVE-2022-35405 | Zoho ManageEngine Multiple Products Remote Code Execution Vulnerability | Nuclei |
| CVE-2022-35914 | Teclib GLPI Remote Code Execution Vulnerability | Nuclei |
| CVE-2022-36537 | ZK Framework AuUploader Unspecified Vulnerability | Nuclei |
| CVE-2022-36804 | Atlassian Bitbucket Server and Data Center Command Injection Vulnerability | Nuclei |
| CVE-2022-37042 | Synacor Zimbra Collaboration Suite (ZCS) Authentication Bypass Vulnerability | Nuclei |
| CVE-2022-40684 | Fortinet Multiple Products Authentication Bypass Vulnerability | Nuclei |
| CVE-2022-41678 | Apache ActiveMQ < 5.16.5/5.17.3 - Remote Code Execution | Nuclei |
| CVE-2022-43939 | Hitachi Vantara Pentaho BA Server Authorization Bypass Vulnerability | Nuclei |
| CVE-2022-44588 | Cryptocurrency Widgets Pack (CVE-2022-44588) | Agent Asteroid |
| CVE-2022-44727 | PrestaShop lgcookieslaw - SQL Injection | Nuclei |
| CVE-2022-44877 | CWP Control Web Panel OS Command Injection Vulnerability | Nuclei |
| CVE-2022-46169 | Cacti Command Injection Vulnerability | Nuclei |
| CVE-2022-47945 | Thinkphp Lang - Local File Inclusion | Nuclei |
| CVE-2022-47966 | Zoho ManageEngine Multiple Products Remote Code Execution Vulnerability | Nuclei |
| CVE-2022-47986 | IBM Aspera Faspex Code Execution Vulnerability | Nuclei |

</details>

<details><summary><b>2021 — 74 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2021-1497 | Cisco HyperFlex HX Installer Virtual Machine Command Injection Vulnerability | Nuclei |
| CVE-2021-1498 | Cisco HyperFlex HX Data Platform Command Injection Vulnerability | Nuclei |
| CVE-2021-3129 | Laravel Ignition File Upload Vulnerability | Tsunami + Nuclei |
| CVE-2021-3152 | Home Assistant HACS - Local File Inclusion | Nuclei |
| CVE-2021-3223 | Known exploited vulnerability | Custom check |
| CVE-2021-3239 | E-Learning System 1.0 - SQL Injection | Nuclei |
| CVE-2021-4463 | Longjing Technology BEMS API 1.21 - Unauthenticated Arbitrary File Download | Nuclei |
| CVE-2021-5890 | Exchange Server SSRF Vulnerability | Nuclei |
| CVE-2021-20038 | SonicWall SMA 100 Appliances Stack-Based Buffer Overflow Vulnerability | Nuclei |
| CVE-2021-20090 | Arcadyan Buffalo Firmware Path Traversal Vulnerability | Nuclei |
| CVE-2021-20123 | Draytek VigorConnect Path Traversal Vulnerability  | Nuclei |
| CVE-2021-20124 | Draytek VigorConnect Path Traversal Vulnerability  | Nuclei |
| CVE-2021-21246 | OneDev < 4.0.3 - User Access Token Leak | Nuclei |
| CVE-2021-21311 | Adminer Server-Side Request Forgery Vulnerability | Nuclei |
| CVE-2021-21315 | System Information Library for Node.JS Command Injection | Nuclei |
| CVE-2021-21972 | VMware vCenter Server Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2021-21973 | VMware vCenter Server and Cloud Foundation Server Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2021-21975 | VMware Server Side Request Forgery in vRealize Operations Manager API | Nuclei |
| CVE-2021-21985 | VMware vCenter Server Improper Input Validation Vulnerability | Nuclei |
| CVE-2021-22005 | VMware vCenter Server File Upload Vulnerability | Nuclei |
| CVE-2021-22054 | Omnissa Workspace ONE Server-Side Request Forgery | Nuclei |
| CVE-2021-22175 | GitLab Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2021-22205 | GitLab Community and Enterprise Editions Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2021-22214 | Gitlab CE/EE 10.5 - Server-Side Request Forgery | Nuclei |
| CVE-2021-22502 | Micro Focus Operation Bridge Report (OBR) Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-22941 | Citrix ShareFile Improper Access Control Vulnerability | Agent Asteroid |
| CVE-2021-22986 | F5 BIG-IP and BIG-IQ Centralized Management iControl REST Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-23337 | Lodash Template - Server-Side Template Injection (RCE) | Nuclei |
| CVE-2021-23758 | Ajax.NET Professional Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2021-24139 | Photo Gallery by 10Web (CVE-2021-24139) | Agent Asteroid |
| CVE-2021-25646 | Known exploited vulnerability | Custom check |
| CVE-2021-26084 | Atlassian Confluence Server and Data Center Object-Graph Navigation Language (OGNL) Injection Vulnerability | Tsunami + Nuclei |
| CVE-2021-26085 | Atlassian Confluence Server Pre-Authorization Arbitrary File Read Vulnerability | Nuclei |
| CVE-2021-26086 | Atlassian Jira Server and Data Center Path Traversal Vulnerability | Nuclei |
| CVE-2021-26855 | Microsoft Exchange Server Remote Code Execution Vulnerability | Metasploit |
| CVE-2021-26857 | Microsoft Exchange Server Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-27065 | Microsoft Exchange Server Remote Code Execution Vulnerability | Metasploit |
| CVE-2021-27561 | Yealink Device Management Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2021-27876 | Veritas Backup Exec Agent File Access Vulnerability | Metasploit |
| CVE-2021-28481 | Microsoft Exchange - Pre-Auth SSRF / ACL Bypass (ProxyNotFound) | Nuclei |
| CVE-2021-28799 | QNAP NAS Improper Authorization Vulnerability | Nuclei |
| CVE-2021-29441 | Known exploited vulnerability | Custom check |
| CVE-2021-31755 | Tenda AC11 Router Stack Buffer Overflow Vulnerability | Nuclei |
| CVE-2021-32030 | ASUS Routers Improper Authentication Vulnerability | Nuclei |
| CVE-2021-32648 | October CMS Improper Authentication | Agent Asteroid |
| CVE-2021-33044 | Dahua IP Camera Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2021-33045 | Dahua IP Camera Authentication Bypass Vulnerability | Nuclei |
| CVE-2021-35464 | ForgeRock Access Management (AM) Core Server Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2021-35587 | Oracle Fusion Middleware Unspecified Vulnerability | Nuclei |
| CVE-2021-36260 | Hikvision Improper Input Validation | Nuclei |
| CVE-2021-36380 | Sunhillo SureLine OS Command Injection Vulnerablity | Nuclei |
| CVE-2021-38647 | Microsoft Open Management Infrastructure (OMI) Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-39144 | XStream Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-39226 | Grafana Authentication Bypass Vulnerability | Nuclei |
| CVE-2021-39935 | GitLab Community and Enterprise Editions Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2021-40438 | Apache HTTP Server-Side Request Forgery (SSRF) | Nuclei |
| CVE-2021-40539 | Zoho ManageEngine ADSelfService Plus Authentication Bypass Vulnerability | Tsunami + Nuclei |
| CVE-2021-40655 | D-Link DIR-605 Router Information Disclosure Vulnerability | Agent Asteroid |
| CVE-2021-40870 | Aviatrix Controller Unrestricted Upload of File | Nuclei |
| CVE-2021-41277 | Metabase GeoJSON API Local File Inclusion Vulnerability | Custom check |
| CVE-2021-41773 | Apache HTTP Server Path Traversal Vulnerability | Tsunami + Nuclei |
| CVE-2021-42013 | Apache HTTP Server Path Traversal Vulnerability | Nuclei |
| CVE-2021-42237 | Sitecore XP Remote Command Execution Vulnerability | Nuclei |
| CVE-2021-42258 | BQE BillQuick Web Suite SQL Injection Vulnerability | Nuclei |
| CVE-2021-42392 | H2 Database Console - JNDI Injection RCE | Nuclei |
| CVE-2021-43798 | Grafana Path Traversal Vulnerability | Nuclei |
| CVE-2021-44077 | Zoho ManageEngine ServiceDesk Plus Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-44228 | Apache Log4j2 Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-44515 | Zoho Desktop Central Authentication Bypass Vulnerability | Nuclei |
| CVE-2021-44529 | Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) Code Injection Vulnerability  | Nuclei |
| CVE-2021-45046 | Apache Log4j2 Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2021-45328 | Gitea CVE-2021-45328 POTENTIAL EXPOSURE | Agent Asteroid |
| CVE-2021-45382 | D-Link Multiple Routers Remote Code Execution Vulnerability | Nuclei |
| CVE-2021-46371 | AntD Admin - Sensitive Information Disclosure | Nuclei |

</details>

<details><summary><b>2020 — 51 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2020-0796 | Microsoft SMBv3 Remote Code Execution Vulnerability | Metasploit |
| CVE-2020-1938 | Apache Tomcat Improper Privilege Management Vulnerability | Metasploit + Tsunami |
| CVE-2020-1956 | Apache Kylin OS Command Injection Vulnerability | Nuclei |
| CVE-2020-2551 | Oracle Fusion Middleware Unspecified Vulnerability | Custom check + Agent Asteroid |
| CVE-2020-2555 | Oracle Multiple Products Remote Code Execution Vulnerability | Metasploit + Agent Asteroid |
| CVE-2020-3452 | Cisco ASA and FTD Read-Only Path Traversal Vulnerability | Tsunami + Nuclei |
| CVE-2020-3952 | VMware vCenter Server Information Disclosure Vulnerability | Metasploit |
| CVE-2020-5410 | VMware Tanzu Spring Cloud Config Directory Traversal Vulnerability | Nuclei |
| CVE-2020-5722 | Grandstream Networks UCM6200 Series SQL Injection Vulnerability | Metasploit |
| CVE-2020-5847 | Unraid Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-5849 | Unraid Authentication Bypass Vulnerability | Metasploit + Nuclei |
| CVE-2020-5902 | F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-6207 | SAP Solution Manager Missing Authentication for Critical Function Vulnerability | Nuclei |
| CVE-2020-6287 | SAP NetWeaver Missing Authentication for Critical Function Vulnerability | Nuclei |
| CVE-2020-7247 | OpenSMTPD Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-7796 | Synacor Zimbra Collaboration Suite (ZCS) Server-Side Request Forgery Vulnerability | Nuclei |
| CVE-2020-7961 | Liferay Portal Deserialization of Untrusted Data Vulnerability | Tsunami + Nuclei |
| CVE-2020-8193 | Citrix ADC, Gateway, and SD-WAN WANOP Appliance Authorization Bypass Vulnerability | Nuclei |
| CVE-2020-8515 | Multiple DrayTek Vigor Routers Web Management Page Vulnerability | Nuclei |
| CVE-2020-8644 | PlaySMS Server-Side Template Injection Vulnerability | Nuclei |
| CVE-2020-8657 | EyesOfNetwork Use of Hard-Coded Credentials Vulnerability | Metasploit |
| CVE-2020-9054 | Zyxel Multiple NAS Devices OS Command Injection Vulnerability | Nuclei |
| CVE-2020-10148 | SolarWinds Orion Authentication Bypass Vulnerability | Nuclei |
| CVE-2020-10189 | Zoho ManageEngine Desktop Central File Upload Vulnerability | Metasploit |
| CVE-2020-10199 | Sonatype Nexus Repository Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-10532 | WatchGuard Fireware AD Helper Component - Credentials Disclosure | Nuclei |
| CVE-2020-11738 | WordPress Snap Creek Duplicator Plugin File Download Vulnerability | Nuclei |
| CVE-2020-11978 | Apache Airflow Command Injection | Nuclei |
| CVE-2020-13927 | Apache Airflow's Experimental API Authentication Bypass | Nuclei |
| CVE-2020-14644 | Oracle WebLogic Server Remote Code Execution Vulnerability | Agent Asteroid |
| CVE-2020-14750 | Oracle WebLogic Server Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2020-14864 | Oracle Business Intelligence Enterprise Edition Path Transversal | Nuclei |
| CVE-2020-14882 | Oracle WebLogic Server Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2020-14883 | Oracle WebLogic Server Unspecified Vulnerability | Custom check |
| CVE-2020-15415 | DrayTek Multiple Vigor Routers OS Command Injection Vulnerability | Agent Asteroid |
| CVE-2020-15505 | Ivanti MobileIron Multiple Products Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-16846 | SaltStack Salt Shell Injection Vulnerability | Nuclei |
| CVE-2020-17463 | Fuel CMS SQL Injection Vulnerability | Nuclei |
| CVE-2020-17496 | vBulletin PHP Module Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-17519 | Apache Flink Improper Access Control Vulnerability | Custom check |
| CVE-2020-17530 | Apache Struts Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-25078 | D-Link DCS-2530L and DCS-2670L Devices Unspecified Vulnerability | Nuclei |
| CVE-2020-25213 | WordPress File Manager Plugin Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-25223 | Sophos SG UTM Remote Code Execution Vulnerability | Nuclei |
| CVE-2020-25506 | D-Link DNS-320 Device Command Injection Vulnerability | Nuclei |
| CVE-2020-26919 | Netgear JGS516PE Devices Missing Function Level Access Control Vulnerability | Nuclei |
| CVE-2020-29134 | TOTVS Fluig <= 1.7.0 - Arbitrary File Read | Nuclei |
| CVE-2020-29557 | D-Link DIR-825 R1 Devices Buffer Overflow Vulnerability | Nuclei |
| CVE-2020-29583 | Zyxel Multiple Products Use of Hard-Coded Credentials Vulnerability | Nuclei |
| CVE-2020-35234 | WordPress Easy WP SMTP - Log Exposure | Nuclei |
| CVE-2020-37123 | Pinger 1.0 - Remote Code Execution | Nuclei |

</details>

<details><summary><b>2019 — 48 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2019-0193 | Apache Solr DataImportHandler Code Injection Vulnerability | Nuclei |
| CVE-2019-0708 | Microsoft Remote Desktop Services Remote Code Execution Vulnerability | Metasploit |
| CVE-2019-1653 | Cisco Small Business RV320 and RV325 Routers Information Disclosure Vulnerability | Nuclei |
| CVE-2019-2616 | Oracle BI Publisher Unauthorized Access Vulnerability | Nuclei |
| CVE-2019-2725 | Oracle WebLogic Server, Injection | Nuclei |
| CVE-2019-3396 | Atlassian Confluence Server and Data Center Server-Side Template Injection Vulnerability | Nuclei |
| CVE-2019-3398 | Atlassian Confluence Server and Data Center Path Traversal Vulnerability | Nuclei |
| CVE-2019-3929 | Crestron Multiple Products Command Injection Vulnerability | Nuclei |
| CVE-2019-5418 | Rails Ruby on Rails Path Traversal Vulnerability | Nuclei |
| CVE-2019-6340 | Drupal Core Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2019-7192 | QNAP Photo Station Improper Access Control Vulnerability | Nuclei |
| CVE-2019-7193 | QNAP QTS Improper Input Validation Vulnerability | Agent Asteroid |
| CVE-2019-7194 | QNAP Photo Station Path Traversal Vulnerability | Metasploit |
| CVE-2019-7195 | QNAP Photo Station Path Traversal Vulnerability | Metasploit |
| CVE-2019-7238 | Sonatype Nexus Repository Manager Incorrect Access Control Vulnerability | Nuclei |
| CVE-2019-7256 | Nice Linear eMerge E3-Series OS Command Injection Vulnerability | Nuclei |
| CVE-2019-7481 | SonicWall SMA100 SQL Injection Vulnerability | Nuclei |
| CVE-2019-7609 | Kibana Arbitrary Code Execution | Nuclei |
| CVE-2019-9082 | ThinkPHP Remote Code Execution Vulnerability | Metasploit |
| CVE-2019-9193 | Known exploited vulnerability | Custom check |
| CVE-2019-9621 | Synacor Zimbra Collaboration Suite (ZCS) Server-Side Request Forgery (SSRF) Vulnerability | Nuclei |
| CVE-2019-9670 | Synacor Zimbra Collaboration Suite (ZCS) Improper Restriction of XML External Entity Reference | Nuclei |
| CVE-2019-9874 | Sitecore CMS and Experience Platform (XP) Deserialization Vulnerability | Agent Asteroid |
| CVE-2019-9978 | WordPress Social Warfare Plugin Cross-Site Scripting (XSS) Vulnerability | Nuclei |
| CVE-2019-10068 | Kentico Xperience Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2019-10758 | MongoDB mongo-express Remote Code Execution Vulnerability | Nuclei |
| CVE-2019-11043 | PHP FastCGI Process Manager (FPM) Buffer Overflow Vulnerability | Metasploit |
| CVE-2019-11510 | Ivanti Pulse Connect Secure Arbitrary File Read Vulnerability | Nuclei |
| CVE-2019-11580 | Atlassian Crowd and Crowd Data Center Remote Code Execution Vulnerability | Nuclei |
| CVE-2019-11581 | Atlassian Jira Server and Data Center Server-Side Template Injection Vulnerability | Nuclei |
| CVE-2019-12409 | Known exploited vulnerability | Custom check |
| CVE-2019-12935 | Shopware < 5.5.8 - Cross-Site Scripting | Nuclei |
| CVE-2019-12989 | Citrix SD-WAN and NetScaler SQL Injection Vulnerability | Agent Asteroid |
| CVE-2019-12991 | Citrix SD-WAN and NetScaler Command Injection Vulnerability | Agent Asteroid |
| CVE-2019-13608 | Citrix StoreFront Server XML External Entity (XXE) Processing Vulnerability | Nuclei |
| CVE-2019-14793 | Meta Box (CVE-2019-14793) | Agent Asteroid |
| CVE-2019-15107 | Webmin Command Injection Vulnerability | Nuclei |
| CVE-2019-16057 | D-Link DNS-320 Remote Code Execution Vulnerability | Nuclei |
| CVE-2019-16278 | Nostromo nhttpd Directory Traversal Vulnerability | Agent Asteroid |
| CVE-2019-16759 | vBulletin PHP Module Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2019-16920 | D-Link Multiple Routers Command Injection Vulnerability | Nuclei |
| CVE-2019-17558 | Apache Solr VelocityResponseWriter Plug-In Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2019-18935 | Progress Telerik UI for ASP.NET AJAX Deserialization of Untrusted Data Vulnerability | Nuclei |
| CVE-2019-19781 | Citrix ADC, Gateway, and SD-WAN WANOP Appliance Code Execution Vulnerability | Nuclei |
| CVE-2019-20085 | TVT NVMS-1000 Directory Traversal Vulnerability | Nuclei |
| CVE-2019-20933 | Known exploited vulnerability | Custom check |
| CVE-2019-25246 | BEWARD N100 H.264 VGA IP Camera M2.1.6 - Arbitrary File Disclosure | Nuclei |
| CVE-2019-1003030 | Jenkins Matrix Project Plugin Remote Code Execution Vulnerability | Nuclei |

</details>

<details><summary><b>2018 — 28 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2018-0151 | Cisco IOS Software and Cisco IOS XE Software Quality of Service Remote Code Execution Vulnerability | Custom check |
| CVE-2018-0181 | Redis Unauthorized Access Vulnerability | Nuclei |
| CVE-2018-0296 | Cisco Adaptive Security Appliance (ASA) Denial-of-Service Vulnerability | Nuclei |
| CVE-2018-1273 | VMware Tanzu Spring Data Commons Property Binder Vulnerability | Nuclei |
| CVE-2018-2628 | Oracle WebLogic Server Unspecified Vulnerability | Metasploit |
| CVE-2018-6530 | D-Link Multiple Routers OS Command Injection Vulnerability | Nuclei |
| CVE-2018-6789 | Exim Buffer Overflow Vulnerability | Agent Asteroid |
| CVE-2018-6961 | VMware SD-WAN Edge by VeloCloud Command Injection Vulnerability | Nuclei |
| CVE-2018-7600 | Drupal Core Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2018-7602 | Drupal Core Remote Code Execution Vulnerability | Nuclei |
| CVE-2018-7765 | Schneider Electric U.motion Builder - SQL Injection | Nuclei |
| CVE-2018-7841 | Schneider Electric U.motion Builder SQL Injection Vulnerability | Agent Asteroid |
| CVE-2018-10561 | Dasan GPON Routers Authentication Bypass Vulnerability | Agent Asteroid |
| CVE-2018-10562 | Dasan GPON Routers Command Injection Vulnerability | Nuclei + Agent Asteroid |
| CVE-2018-11138 | Quest KACE System Management Appliance Remote Command Execution Vulnerability | Metasploit |
| CVE-2018-11714 | TP-LINK WR840N v6 up to 0.9.1 4.16 - Improper Authentication | Nuclei |
| CVE-2018-11776 | Apache Struts Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2018-13379 | Fortinet FortiOS SSL VPN Path Traversal Vulnerability | Nuclei |
| CVE-2018-13382 | Fortinet FortiOS and FortiProxy Improper Authorization | Agent Asteroid |
| CVE-2018-14558 | Tenda AC7, AC9, and AC10 Routers Command Injection Vulnerability | Agent Asteroid |
| CVE-2018-14667 | Red Hat JBoss RichFaces Framework Expression Language Injection Vulnerability | Agent Asteroid |
| CVE-2018-14933 | NUUO NVRmini Devices OS Command Injection Vulnerability  | Agent Asteroid |
| CVE-2018-15133 | Laravel Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2018-15961 | Adobe ColdFusion Unrestricted File Upload Vulnerability | Nuclei |
| CVE-2018-18809 | TIBCO JasperReports Library Directory Traversal Vulnerability | Nuclei |
| CVE-2018-19410 | Paessler PRTG Network Monitor Local File Inclusion Vulnerability | Agent Asteroid |
| CVE-2018-20062 | ThinkPHP "noneCms" Remote Code Execution Vulnerability | Metasploit |
| CVE-2018-1000861 | Jenkins Stapler Web Framework Deserialization of Untrusted Data Vulnerability | Nuclei |

</details>

<details><summary><b>2017 — 34 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2017-0143 | Microsoft Windows Server Message Block (SMBv1) Remote Code Execution Vulnerability | Metasploit |
| CVE-2017-0144 | Microsoft SMBv1 Remote Code Execution Vulnerability | Metasploit |
| CVE-2017-0145 | Microsoft SMBv1 Remote Code Execution Vulnerability | Metasploit |
| CVE-2017-0147 | Microsoft Windows SMBv1 Information Disclosure Vulnerability | Metasploit + Agent Asteroid |
| CVE-2017-0148 | Microsoft SMBv1 Server Remote Code Execution Vulnerability | Metasploit + Agent Asteroid |
| CVE-2017-3066 | Adobe ColdFusion Deserialization Vulnerability | Agent Asteroid |
| CVE-2017-3506 | Oracle WebLogic Server OS Command Injection Vulnerability | Nuclei |
| CVE-2017-3881 | Cisco IOS and IOS XE Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-5521 | NETGEAR Multiple Devices Exposure of Sensitive Information Vulnerability | Nuclei |
| CVE-2017-5638 | Apache Struts Remote Code Execution Vulnerability | Tsunami + Nuclei |
| CVE-2017-5689 | Intel Active Management Technology (AMT), Small Business Technology (SBT), and Standard Manageability Privilege Escalation Vulnerability | Nuclei |
| CVE-2017-7269 | Microsoft Windows Server Buffer Overflow Vulnerability | Metasploit |
| CVE-2017-7494 | Samba Remote Code Execution Vulnerability | Metasploit |
| CVE-2017-7504 | JBossMQ HTTP Invocation Layer (HTTPServerILServlet) - Unauthenticated Java Deserialization | Nuclei |
| CVE-2017-7615 | Known exploited vulnerability | Custom check |
| CVE-2017-7921 | Hikvision Multiple Products Improper Authentication Vulnerability | Nuclei |
| CVE-2017-8046 | Spring Data REST < 2.6.9 (Ingalls SR9) / 3.0.1 (Kay SR1) - PATCH Request Remote Code Execution | Nuclei |
| CVE-2017-9248 | Progress Telerik UI for ASP.NET AJAX and Sitefinity Cryptographic Weakness Vulnerability | Nuclei |
| CVE-2017-9791 | Apache Struts 1 Improper Input Validation Vulnerability | Nuclei |
| CVE-2017-9805 | Apache Struts Deserialization of Untrusted Data Vulnerability | Tsunami + Nuclei |
| CVE-2017-9822 | DotNetNuke (DNN) Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-9841 | PHPUnit Command Injection Vulnerability | Nuclei |
| CVE-2017-10271 | Oracle Corporation WebLogic Server Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-11317 | Telerik UI for ASP.NET AJAX Unrestricted File Upload Vulnerability | Nuclei |
| CVE-2017-11357 | Telerik UI for ASP.NET AJAX Insecure Direct Object Reference Vulnerability | Nuclei |
| CVE-2017-12149 | Red Hat JBoss Application Server Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-12615 | Apache Tomcat on Windows Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-12617 | Apache Tomcat Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-12637 | SAP NetWeaver Directory Traversal Vulnerability | Nuclei |
| CVE-2017-15944 | Palo Alto Networks PAN-OS Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-17562 | Embedthis GoAhead Remote Code Execution Vulnerability | Nuclei |
| CVE-2017-18368 | Zyxel P660HN-T1A Routers Command Injection Vulnerability | Nuclei |
| CVE-2017-1000353 | Jenkins Remote Code Execution Vulnerability | Tsunami |
| CVE-2017-1000486 | Primetek Primefaces Remote Code Execution Vulnerability | Nuclei |

</details>

<details><summary><b>2016 — 9 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2016-0752 | Ruby on Rails Directory Traversal Vulnerability | Nuclei |
| CVE-2016-1555 | NETGEAR Multiple WAP Devices Command Injection Vulnerability | Nuclei |
| CVE-2016-2386 | SAP NetWeaver SQL Injection Vulnerability | Agent Asteroid |
| CVE-2016-3088 | Apache ActiveMQ Improper Input Validation Vulnerability | Nuclei |
| CVE-2016-4437 | Apache Shiro Code Execution Vulnerability | Nuclei |
| CVE-2016-6277 | NETGEAR Multiple Routers Remote Code Execution Vulnerability | Nuclei |
| CVE-2016-10174 | NETGEAR WNR2000v5 Router Buffer Overflow Vulnerability | Nuclei |
| CVE-2016-15043 | WP Mobile Detector (CVE-2016-15043) | Agent Asteroid |
| CVE-2016-20017 | D-Link DSL-2750B Devices Command Injection Vulnerability | Metasploit + Nuclei |

</details>

<details><summary><b>2015 — 7 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2015-1187 | D-Link and TRENDnet Multiple Devices Remote Code Execution Vulnerability | Metasploit |
| CVE-2015-1427 | Elasticsearch Groovy Scripting Engine Remote Code Execution Vulnerability | Nuclei |
| CVE-2015-1635 | Microsoft HTTP.sys Remote Code Execution Vulnerability | Custom check |
| CVE-2015-3035 | TP-Link Multiple Archer Devices Directory Traversal Vulnerability | Nuclei |
| CVE-2015-4852 | Oracle WebLogic Server Deserialization of Untrusted Data Vulnerability | Agent Asteroid |
| CVE-2015-7450 | IBM WebSphere Application Server and Server Hypervisor Edition Code Injection. | Nuclei |
| CVE-2015-8562 | Known exploited vulnerability | Custom check |

</details>

<details><summary><b>2014 — 8 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2014-0160 | OpenSSL Information Disclosure Vulnerability | Metasploit |
| CVE-2014-0780 | InduSoft Web Studio NTWebServer Directory Traversal Vulnerability | Agent Asteroid |
| CVE-2014-2120 | Cisco Adaptive Security Appliance (ASA) Cross-Site Scripting (XSS) Vulnerability | Agent Asteroid |
| CVE-2014-3120 | Elasticsearch Remote Code Execution Vulnerability | Nuclei |
| CVE-2014-6271 | GNU Bourne-Again Shell (Bash) Arbitrary Code Execution Vulnerability | Nuclei |
| CVE-2014-6287 | Rejetto HTTP File Server (HFS) Remote Code Execution Vulnerability | Nuclei |
| CVE-2014-7169 | GNU Bourne-Again Shell (Bash) Arbitrary Code Execution Vulnerability | Agent Asteroid |
| CVE-2014-8361 | Realtek SDK Improper Input Validation Vulnerability | Nuclei |

</details>

<details><summary><b>2013 — 6 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2013-0625 | Adobe ColdFusion Authentication Bypass Vulnerability | Metasploit |
| CVE-2013-0629 | Adobe ColdFusion Directory Traversal Vulnerability | Metasploit |
| CVE-2013-0631 | Adobe ColdFusion Information Disclosure Vulnerability | Metasploit |
| CVE-2013-0632 | Adobe ColdFusion Authentication Bypass Vulnerability | Metasploit + Nuclei |
| CVE-2013-2251 | Apache Struts Improper Input Validation Vulnerability | Nuclei |
| CVE-2013-4810 | HP Multiple Products Remote Code Execution Vulnerability | Nuclei |

</details>

<details><summary><b>2012 — 3 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2012-1823 | PHP-CGI Query String Parameter Vulnerability | Metasploit + Tsunami |
| CVE-2012-3152 | Oracle Fusion Middleware Unspecified Vulnerability | Nuclei |
| CVE-2012-3153 | Known exploited vulnerability | Nuclei |

</details>

<details><summary><b>2011 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2011-3600 | Apache OFBiz - XML External Entity Injection | Nuclei |

</details>

<details><summary><b>2010 — 5 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2010-0738 | Red Hat JBoss Authentication Bypass Vulnerability | Nuclei |
| CVE-2010-1428 | Red Hat JBoss Information Disclosure Vulnerability | Nuclei |
| CVE-2010-1871 | Red Hat Linux JBoss Seam 2 Remote Code Execution Vulnerability | Metasploit |
| CVE-2010-2861 | Adobe ColdFusion Directory Traversal Vulnerability | Nuclei |
| CVE-2010-4344 | Exim Heap-Based Buffer Overflow Vulnerability | Agent Asteroid |

</details>

<details><summary><b>2009 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| CVE-2009-1151 | phpMyAdmin Remote Code Execution Vulnerability | Nuclei |

</details>

### Non-CVE exposure checks

| Check | Detector |
| --- | --- |
| GHSA-cr3w-cw5w-h3fj | Custom Exploit by Ostorlab |
| Cyberpanel-rce | Official Nuclei template. |
| JETPACK_DATA_EXPOSURE | Custom Exploit by Ostorlab: included in Agent Asteroid. |
| Selenium exposure. | Official Nuclei template. |
| Generic Path Traversal vulnerabilities. | Tsunami Detector. |
| Apache NiFi API Exposed UI. | Tsunami Detector. |
| Exposed Argo Workflows instances. | Tsunami Detector. |
| Exposed Docker API. | Tsunami Detector. |
| Exposed Elasticsearch API. | Tsunami Detector. |
| Exposed Hadoop Yarn ResourceManager API. | Tsunami Detector. |
| Exposed Jenkins UI. | Tsunami Detector. |
| Exposed Jupyter Notebook. | Tsunami Detector. |
| Exposed Kubernetes API. | Tsunami Detector. |
| Information leak via Kubernetes read-only-port feature. | Tsunami Detector. |
| PHPUnit Exposed Vulnerable eval-stdin.php. | Tsunami Detector. |
| Exposed Spring Boot Actuator Endpoint. | Tsunami Detector. |
| WordPress Exposed Installation Page. | Tsunami Detector. |
| Consul RCE. | Tsunami Detector. |
| Unauthenticated Redis allowing RCE. | Tsunami Detector. |
| Cisco SMI Protocol. | Tsunami Detector. |
| Apache Solr RemoteStreaming Arbitrary File Reading. | Tsunami Detector. |
| Jira Authentication Bypass Vulnerability. | Tsunami Detector. |
| Kubernetes Open Access Remote Code Execution. | Tsunami Detector. |
| Selenium Grid - RCE via Chrome webdriver. | Tsunami Detector. |
| GoCD Pre-Auth Arbitrary File Reading vulnerability. | Tsunami Detector. |

Agent Asteroid also ships three non-CVE exposure checks: unauthenticated ADB,
the Docker Registry API, and the Jetpack contact-form data exposure. The Jetpack
check is already listed above; the other two run as part of Agent Asteroid.

### Not detected

1,205 CISA KEV entries are not detected because they are local, require
authentication or user interaction, have no public template, or cannot be
checked without modifying the target. One entry is in progress. The full status
table, with the reason for every entry, is in
[docs/coverage-status.md](docs/coverage-status.md).

### Agent Asteroid offline inventory checks

The KEV agent group does not run Agent Asteroid's offline inventory assessor.
Its 85 inventory-only CVEs are listed below for reference. Run
them from the [Agent Asteroid](https://github.com/Ostorlab/agent_asteroid)
repository with:

```shell
python -m agent.utils.inventory inventory.json
```

<details><summary><b>2026 — 64 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2026-0263](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0263.py) | Owner-inventory-only assessment of PAN-OS IKEv2 CVE-2026-0263 | Offline inventory |
| [CVE-2026-0264](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0264.py) | Owner-inventory-only assessment of PAN-OS DNS CVE-2026-0264 | Offline inventory |
| [CVE-2026-0265](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0265.py) | Owner-inventory-only assessment of PAN-OS CAS CVE-2026-0265 | Offline inventory |
| [CVE-2026-0288](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0288.py) | Owner-inventory-only PAN-OS Terminal Server Agent CVE-2026-0288 assessment | Offline inventory |
| [CVE-2026-0300](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0300.py) | Owner-inventory-only PAN-OS Authentication Portal CVE-2026-0300 assessment | Offline inventory |
| [CVE-2026-0310](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_0310.py) | Qualified PAN-OS XML-processing CVE-2026-0310 owner-inventory assessment | Offline inventory |
| [CVE-2026-3593](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_3593.py) | Owner-inventory BIND DoH assessment; no memory-corruption probe | Offline inventory |
| [CVE-2026-3630](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_3630.py) | Inventory-only potential exposure assessment for CVE-2026-3630 | Offline inventory |
| [CVE-2026-4800](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_4800.py) | Owner-inventory assessment of lodash template imports, without target I/O | Offline inventory |
| [CVE-2026-6516](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_6516.py) | Inventory-only potential exposure assessment for CVE-2026-6516 | Offline inventory |
| [CVE-2026-8024](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_8024.py) | Inventory-only potential exposure assessment for CVE-2026-8024 | Offline inventory |
| [CVE-2026-8364](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_8364.py) | Owner-inventory assessment of Triofox Server Agent CVE-2026-8364 | Offline inventory |
| [CVE-2026-8644](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_8644.py) | Inventory-only potential exposure assessment for CVE-2026-8644 | Offline inventory |
| [CVE-2026-8713](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_8713.py) | Owner-inventory Avada Builder assessment for CVE-2026-8713; no remote probe | Offline inventory |
| [CVE-2026-8763](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_8763.py) | Owner-inventory assessment of CVE-2026-8763; no remote detector or target I/O | Offline inventory |
| [CVE-2026-9006](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_9006.py) | Inventory-only potential exposure assessment for CVE-2026-9006 | Offline inventory |
| [CVE-2026-9319](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_9319.py) | Inventory-only potential exposure assessment for CVE-2026-9319 | Offline inventory |
| [CVE-2026-11374](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_11374.py) | Inventory-only potential exposure assessment for AD360 predictable SSO tickets | Offline inventory |
| [CVE-2026-11541](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_11541.py) | Inventory-only potential exposure assessment for CVE-2026-11541 | Offline inventory |
| [CVE-2026-11546](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_11546.py) | Inventory-only potential exposure assessment for CVE-2026-11546 | Offline inventory |
| [CVE-2026-11714](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_11714.py) | Inventory-only potential exposure assessment for CVE-2026-11714 | Offline inventory |
| [CVE-2026-14446](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_14446.py) | Inventory-only potential exposure assessment for CVE-2026-14446 | Offline inventory |
| [CVE-2026-14525](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_14525.py) | Inventory-only potential exposure assessment for CVE-2026-14525 | Offline inventory |
| [CVE-2026-15176](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_15176.py) | Qualified owner-inventory assessment for NGINX alias/rewrite CVE-2026-15176 | Offline inventory |
| [CVE-2026-16184](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_16184.py) | Inventory-only potential exposure assessment for CVE-2026-16184 | Offline inventory |
| [CVE-2026-16627](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_16627.py) | Qualified owner inventory for GitLab CI job-modal CVE-2026-16627 | Offline inventory |
| [CVE-2026-20045](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_20045.py) | Qualified CVE-2026-20045 CUCM-family owner inventory; no HTTP probes | Offline inventory |
| [CVE-2026-20093](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_20093.py) | Qualified Cisco IMC CVE-2026-20093 owner inventory; no password requests | Offline inventory |
| [CVE-2026-20160](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_20160.py) | Owner-inventory assessment for Cisco SSM On-Prem CVE-2026-20160 | Offline inventory |
| [CVE-2026-20896](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_20896.py) | Offline owner-inventory assessment for Gitea Docker proxy authentication | Offline inventory |
| [CVE-2026-28323](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_28323.py) | Owner-inventory SAML applicability for Web Help Desk CVE-2026-28323 | Offline inventory |
| [CVE-2026-29000](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_29000.py) | Owner-inventory assessment of pac4j-jwt CVE-2026-29000, without target I/O | Offline inventory |
| [CVE-2026-29145](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_29145.py) | Qualified owner assessment for Tomcat OCSP CVE-2026-29145 | Offline inventory |
| [CVE-2026-42055](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_42055.py) | Qualified owner-inventory assessment for NGINX upstream CVE-2026-42055 | Offline inventory |
| [CVE-2026-42530](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_42530.py) | Qualified owner-inventory assessment for NGINX HTTP/3 CVE-2026-42530 | Offline inventory |
| [CVE-2026-42533](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_42533.py) | Qualified owner-inventory assessment for NGINX map/regex CVE-2026-42533 | Offline inventory |
| [CVE-2026-42945](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_42945.py) | Qualified owner-inventory assessment for NGINX rewrite CVE-2026-42945 | Offline inventory |
| [CVE-2026-45674](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_45674.py) | Owner-inventory assessment of Netty DNS CVE-2026-45674, without target I/O | Offline inventory |
| [CVE-2026-48360](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_48360.py) | Owner-inventory assessment of Adobe Connect clients, CVE-2026-48360 | Offline inventory |
| [CVE-2026-58062](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_58062.py) | Owner-inventory assessment of CVE-2026-58062; no remote detector or target I/O | Offline inventory |
| [CVE-2026-59650](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_59650.py) | Owner-inventory assessment of CVE-2026-59650; no remote detector or target I/O | Offline inventory |
| [CVE-2026-65182](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_65182.py) | Qualified owner assessment for Tomcat constraint ordering CVE-2026-65182 | Offline inventory |
| [CVE-2026-65637](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_65637.py) | Qualified owner assessment for Tomcat HTTP/2 strict-SNI CVE-2026-65637 | Offline inventory |
| [CVE-2026-65905](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_65905.py) | Qualified owner assessment for Tomcat DIGEST replay CVE-2026-65905 | Offline inventory |
| [CVE-2026-67276](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_67276.py) | Qualified RouterOS SSH RSA CVE-2026-67276 owner-inventory assessment | Offline inventory |
| [CVE-2026-68525](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_68525.py) | Qualified owner assessment for Tomcat FORM constraints CVE-2026-68525 | Offline inventory |
| [CVE-2026-73453](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_73453.py) | Qualified Arista EOS P4Runtime CVE-2026-73453 owner inventory | Offline inventory |
| [CVE-2026-74849](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_74849.py) | Inventory-only potential exposure assessment for CVE-2026-74849 | Offline inventory |
| [CVE-2026-75595](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_75595.py) | Owner-inventory assessment of Netty SNI CVE-2026-75595, without target I/O | Offline inventory |
| [CVE-2026-76461](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_76461.py) | Qualified Cisco Secure Email Gateway CVE-2026-76461 owner inventory | Offline inventory |
| [CVE-2026-76465](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_76465.py) | Qualified MPLS OAM CVE-2026-76465 owner inventory; no packet probes | Offline inventory |
| [CVE-2026-76471](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_76471.py) | Qualified NX-API CVE-2026-76471 owner inventory; no crafted HTTP requests | Offline inventory |
| [CVE-2026-84411](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_84411.py) | Qualified owner-inventory RouterOS web-management CVE-2026-84411 assessment | Offline inventory |
| [CVE-2026-87719](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_87719.py) | Qualified owner inventory for GitLab Duo Chat CVE-2026-87719 | Offline inventory |
| [CVE-2026-89078](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_89078.py) | Offline owner-inventory assessment for CVE-2026-89078 | Offline inventory |
| [CVE-2026-93479](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_93479.py) | Qualified owner-inventory assessment for NGINX root/access-log CVE-2026-93479 | Offline inventory |
| [CVE-2026-93577](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_93577.py) | Offline owner-inventory assessment for CVE-2026-93577 | Offline inventory |
| [CVE-2026-97229](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_97229.py) | Offline owner-inventory assessment for CVE-2026-97229 | Offline inventory |
| [CVE-2026-102084](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_102084.py) | Qualified Junos ADVPN CVE-2026-102084 owner-inventory assessment | Offline inventory |
| [CVE-2026-107406](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_107406.py) | Owner-inventory assessment of NetScaler SAML potential exposure | Offline inventory |
| [CVE-2026-107656](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_107656.py) | Offline FortiSandbox GUI exposure assessment with edition-specific bounds | Offline inventory |
| [CVE-2026-110264](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_110264.py) | Offline owner-inventory assessment for CVE-2026-110264 | Offline inventory |
| [CVE-2026-114625](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_114625.py) | Offline owner-inventory assessment for CVE-2026-114625 | Offline inventory |
| [CVE-2026-115560](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2026_115560.py) | Offline owner-inventory assessment for CVE-2026-115560 | Offline inventory |

</details>

<details><summary><b>2025 — 11 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2025-3085](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_3085.py) | Inventory-only potential exposure assessment for CVE-2025-3085 | Offline inventory |
| [CVE-2025-7659](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_7659.py) | Qualified owner inventory for GitLab Web IDE CVE-2025-7659 | Offline inventory |
| [CVE-2025-13761](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_13761.py) | Qualified owner inventory for GitLab browser CVE-2025-13761 | Offline inventory |
| [CVE-2025-14917](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_14917.py) | Inventory-only potential exposure assessment for CVE-2025-14917 | Offline inventory |
| [CVE-2025-14923](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_14923.py) | Inventory-only potential exposure assessment for CVE-2025-14923 | Offline inventory |
| [CVE-2025-20393](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_20393.py) | Qualified Cisco email quarantine CVE-2025-20393 owner inventory | Offline inventory |
| [CVE-2025-54531](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_54531.py) | Owner Windows plugin-unpacking assessment for TeamCity CVE-2025-54531 | Offline inventory |
| [CVE-2025-62581](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_62581.py) | Inventory-only potential exposure assessment for CVE-2025-62581 | Offline inventory |
| [CVE-2025-62582](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_62582.py) | Inventory-only potential exposure assessment for CVE-2025-62582 | Offline inventory |
| [CVE-2025-64155](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_64155.py) | Owner-inventory assessment of FortiSIEM phMonitor; no remote probe | Offline inventory |
| [CVE-2025-69258](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2025_69258.py) | Inventory-only potential exposure assessment for CVE-2025-69258 | Offline inventory |

</details>

<details><summary><b>2024 — 4 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2024-3596](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2024_3596.py) | Qualified PAN-OS BlastRADIUS owner inventory; no authentication probes | Offline inventory |
| [CVE-2024-9537](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2024_9537.py) | Qualified owner-release assessment for ScienceLogic SL1 CVE-2024-9537 | Offline inventory |
| [CVE-2024-21591](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2024_21591.py) | Qualified Junos J-Web CVE-2024-21591 owner-inventory assessment | Offline inventory |
| [CVE-2024-53298](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2024_53298.py) | Inventory-only potential exposure assessment for CVE-2024-53298 | Offline inventory |

</details>

<details><summary><b>2023 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2023-42282](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2023_42282.py) | Owner-inventory assessment of node-ip CVE-2023-42282 without SSRF probes | Offline inventory |

</details>

<details><summary><b>2022 — 2 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2022-24331](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2022_24331.py) | Owner native GitLab authentication assessment for TeamCity CVE-2022-24331 | Offline inventory |
| [CVE-2022-37601](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2022_37601.py) | Owner-inventory assessment of loader-utils CVE-2022-37601, without target I/O | Offline inventory |

</details>

<details><summary><b>2021 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2021-31914](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2021_31914.py) | Owner server-release and Windows assessment for TeamCity CVE-2021-31914 | Offline inventory |

</details>

<details><summary><b>2020 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2020-1992](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2020_1992.py) | Owner-inventory PAN-OS Varrcvr assessment; no remote daemon probe | Offline inventory |

</details>

<details><summary><b>2019 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2019-19006](https://github.com/Ostorlab/agent_asteroid/blob/main/agent/exploits/cve_2019_19006.py) | Owner framework-module inventory for FreePBX CVE-2019-19006 | Offline inventory |

</details>

## Contributing

Contributions are welcome, especially new detectors for recently exploited
vulnerabilities. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add and test
a detector and how to update the coverage lists.

## License

Apache 2.0. See [LICENSE](LICENSE).
