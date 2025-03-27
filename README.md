# Known Exploited Vulnerabilities (KEV) Detector

## Introduction

This project is dedicated to automate the detection of known exploited vulnerabilities through a single command, it includes exploits for vulnerabilities from:

- [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)  by CISA
- [Tsunami](https://github.com/google/tsunami-security-scanner) by Google 
- [Agent Asteroid](https://github.com/Ostorlab/agent_asteroid) by Ostorlab 
- Bug Bounty Programs

## Requirements

Python 3.9 or greater is required to install KEV via `pip`.

Docker is required to run scans locally. To install docker, please follow these
[instructions](https://docs.docker.com/get-docker/).

## Installing

Ostorlab ships as a Python package on pypi. To install it, simply run the following command if you have `pip` already
installed.

```shell
pip install -U ostorlab
```

## Agent group definition

This repo is an `Agent Group Definition` of the open-source [`ostorlab`](https://github.com/Ostorlab/ostorlab) scanner. An agent
group is nothing but a config file that defines the list of components to run during the scan.

For a full tutorial on how to use Ostorlab CLI, check the following [tutorial](https://oxo.ostorlab.co/tutorials).

By default, Ostorlab KEV agent group `agent_group.yaml` uses the following agents:

- [Agent Nuclei](https://github.com/Ostorlab/agent_nuclei)
- [Agent Tsunami](https://github.com/Ostorlab/agent_tsunami)
- [Agent Nmap](https://github.com/Ostorlab/agent_nmap)
- [Agent Asteroid](https://github.com/Ostorlab/agent_asteroid)
- [Agent Metasploit](https://github.com/Ostorlab/agent_metasploit)

## Getting Started

To perform your first scan, you have several options depending on your target.

Here's how you can get started:

### Scanning an IP Address

To scan an IP address, simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml ip 8.8.8.8
```

And you can scan more than one IP address by specifying them, separated by spaces:

```shell
ostorlab scan run --install -g agent_group.yaml ip 8.8.8.8 1.1.1.1 4.4.4.0/24
```
[![asciicast](https://asciinema.org/a/640606.svg)](https://asciinema.org/a/640606)

### Scanning a Host:

To scan a domain, simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml domain-name www.example.com
```

This command will download and install the required agents specified in the YAML file and perform the scan on the
domain `www.example.com`.
[![asciicast](https://asciinema.org/a/640627.svg)](https://asciinema.org/a/640627)
### Scanning a Link:

To scan a link, simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml link --url https://www.example.com --method GET
```

This command will download and install the required agents specified in the YAML file and perform the scan on the link `https://www.example.com` using the specified method.
[![asciicast](https://asciinema.org/a/640629.svg)](https://asciinema.org/a/640629)
### Targeting all subdomains

To improve the scope of detection, it's possible to enumerate and target subdomains of a given asset by adding `subfinder` and/or `dnsx` to the agent group definition `agent_group.yaml`.

```yaml
agent:
  ...
  - key: agent/ostorlab/subfinder
  - key: agent/ostorlab/dnsx
  ...
```

And then run it on the domain you would like to target:

```shell
ostorlab scan run --install -g agent_group.yaml domain-name example.com
```

> [!TIP]
> The default settings use public DNS servers which can affect enumeration results for very large domains due to rate limiting or caching.
> Consider using a custom list of DNS resolvers.
> To do so, set resolvers arguments in the `Amass` and `Subfinder` agents.


### Docker Image

To run `oxo` in a container, you may use the publicly available image and run the following command:  

```shell
docker run -v /var/run/docker.sock:/var/run/docker.sock -v ./agent_group.yaml:/agent_group.yaml  ostorlab/oxo:latest scan run --install -g /agent_group.yaml link --url https://www.example.com --method GET
```

Notes:
* The command starts directly with: `scan run`, this is because the `ostorlab/oxo` image has `oxo` as an `entrypoint`.
* It is important to mount the docker socket so `oxo` can create the agent in the host machine.


### Scan Progress

To see the scan progress, use the scan list command:

```shell
ostorlab scan list
```

### Access Results

List findings in a particular scan:

```shell
ostorlab vulnz list -s <scan-id>
```

To list the details of a vulnerability:

```shell
ostorlab vulnz describe -v <vuln-id>
```
[![asciicast](https://asciinema.org/a/640566.svg)](https://asciinema.org/a/640566)
## Current Coverage

For the moment, we are currently focused on the CISA KEV Database and Google Tsunami.

| CVE ID                                                  | Implemented | Detail                                                  | Published Date |
|:--------------------------------------------------------|:-----------:|:--------------------------------------------------------|:--------------:|
| CVE-2025-1974                                           |      ✅      | Official Nuclei template.                               |   2025-03-24   |
| CVE-2025-29927                                          |      ✅      | Official Nuclei template.                               |   2025-03-21   |
| CVE-2025-29891                                          |      ✅      | Custom Nuclei template.                                 |   2025-03-12   |
| CVE-2025-24813                                          |      ✅      | Custom Nuclei template.                                 |   2025-03-10   |
| CVE-2025-27636                                          |      ✅      | Custom Nuclei template.                                 |   2025-03-09   |
| CVE-2024-48248                                          |      ✅      | Official Nuclei template.                               |   2025-03-04   |
| CVE-2025-0108                                           |      ✅      | Custom Nuclei template.                                 |   2025-02-12   |
| CVE-2025-0674                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-02-04   |
| CVE-2025-0890                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-02-04   |
| CVE-2024-12084                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-01-15   |
| CVE-2024-55591                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-01-14   |
| CVE-2024-13159                                          |      ✅      | Official Nuclei template.                               |   2025-01-14   |
| CVE-2024-13160                                          |      ✅      | Official Nuclei template.                               |   2025-01-14   |
| CVE-2024-12847                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-01-10   |
| CVE-2024-53704                                          |      ✅      | Custom Nuclei template.                                 |   2025-01-09   |
| CVE-2025-0282                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2025-01-08   |
| CVE-2024-50603                                          |      ✅      | Custom Nuclei template.                                 |   2025-01-07   |
| CVE-2024-12987                                          |      ✅      | Custom Nuclei template.                                 |   2024-12-27   |
| CVE-2024-56145                                          |      ✅      | Custom Nuclei template.                                 |   2024-12-18   |
| CVE-2023-34990                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-18   |
| CVE-2024-51479                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-17   |
| CVE-2024-50379                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-17   |
| CVE-2024-38819                                          |      ✅      | Official Nuclei template.                               |   2024-12-17   |
| CVE-2024-55956                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-13   |
| CVE-2024-11205                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-10   |
| CVE-2024-11772                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-10   |
| CVE-2024-11639                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-10   |
| CVE-2024-12209                                          |      ✅      | Official Nuclei template.                               |   2024-12-08   |
| CVE-2024-54134                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-04   |
| CVE-2024-10905                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-12-02   |
| CVE-2024-8672                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-28   |
| CVE-2024-11667                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-27   |
| CVE-2024-10781                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-26   |
| CVE-2024-10542                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-26   |
| CVE-2024-11680                                          |      ✅      | Official Nuclei template.                               |   2024-11-26   |
| CVE-2024-10924                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-11-20   |
| CVE-2024-42450                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-19   |
| CVE-2024-0012                                           |      ✅      | Official Nuclei template.                               |   2024-11-18   |
| CVE-2024-21287                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-11-18   |
| CVE-2024-52875                                          |      ✅      | Official Nuclei template.                               |   2024-11-17   |
| CVE-2024-50340                                          |      ✅      | Official Nuclei template.                               |   2024-11-06   |
| CVE-2024-10914                                          |      ✅      | Official Nuclei template.                               |   2024-11-06   |
| CVE-2024-43919                                          |      ✅      | Official Nuclei template.                               |   2024-11-01   |
| CVE-2024-50550                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-10-29   |
| CVE-2024-50498                                          |      ✅      | Official Nuclei template.                               |   2024-10-28   |
| CVE-2024-50623                                          |      ✅      | Official Nuclei template.                               |   2024-10-27   |
| Cyberpanel-rce                                          |      ✅      | Official Nuclei template.                               |   2024-10-27   |
| CVE-2024-41713                                          |      ✅      | Official Nuclei template.                               |   2024-10-21   |
| CVE-2024-35286                                          |      ✅      | Official Nuclei template.                               |   2024-10-21   |
| CVE-2024-9634                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-10-15   |
| JETPACK_DATA_EXPOSURE                                   |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-10-15   |
| CVE-2024-9164                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-10-11   |
| CVE-2024-9487                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-10-10   |
| CVE-2024-5910                                           |      ✅      | Official Nuclei template.                               |   2024-10-07   |
| CVE-2024-47176                                          |      ✅      | Official Nuclei template.                               |   2024-09-26   |
| CVE-2024-8963                                           |      ✅      | Official Nuclei template.                               |   2024-09-19   |
| CVE-2024-38812                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-09-17   |
| CVE-2024-46938                                          |      ✅      | Official Nuclei template.                               |   2024-09-15   |
| CVE-2024-8522                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-09-12   |
| CVE-2024-9463                                           |      ✅      | Official Nuclei template.                               |   2024-09-10   |
| CVE-2024-9465                                           |      ✅      | Official Nuclei template.                               |   2024-09-10   |
| CVE-2024-45409                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-09-10   |
| CVE-2024-40711                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-09-07   |
| CVE-2024-45519                                          |      ✅      | Official Nuclei template.                               |   2024-09-06   |
| CVE-2024-20440                                          |      ✅      | Official Nuclei template.                               |   2024-09-06   |
| CVE-2024-45195                                          |      ✅      | Official Nuclei template.                               |   2024-09-04   |
| CVE-2024-45507                                          |      ✅      | Official Nuclei template.                               |   2024-09-04   |
| CVE-2024-20439                                          |      ✅      | Official Nuclei template.                               |   2024-09-04   |
| CVE-2024-6633                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-27   |
| CVE-2024-6670                                           |      ✅      | Official Nuclei template.                               |   2024-08-29   |
| CVE-2024-39717                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-22   |
| CVE-2024-43399                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-19   |
| CVE-2024-40766                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-23   |
| CVE-2024-6386                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-21   |
| CVE-2024-28987                                          |      ✅      | Official Nuclei template.                               |   2024-08-21   |
| CVE-2024-5932                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-08-19   |
| CVE-2024-7593                                           |      ✅      | Official Nuclei template.                               |   2024-08-13   |
| CVE-2024-43044                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-07   |
| CVE-2024-6782                                           |      ✅      | Official Nuclei template.                               |   2024-08-06   |
| CVE-2024-7029                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-08-02   |
| CVE-2024-38856                                          |      ✅      | Official Nuclei template.                               |   2024-08-05   |
| CVE-2024-7120                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-07-26   |
| CVE-2024-6385                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-07-11   |
| CVE-2024-5217                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-07-10   |
| CVE-2024-4879                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-07-10   |
| CVE-2024-6387                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-07-01   |
| CVE-2024-36404                                          |      ✅      | Official Nuclei template.                               |   2024-07-02   |
| CVE-2024-36401                                          |      ✅      | Official Nuclei template.                               |   2024-07-01   |
| CVE-2024-36991                                          |      ✅      | Official Nuclei template.                               |   2024-07-01   |
| CVE-2024-4885                                           |      ✅      | Official Nuclei template.                               |   2024-06-25   |
| CVE-2022-24816                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-06-24   |
| CVE-2024-34102                                          |      ✅      | Official Nuclei template.                               |   2024-06-13   |
| CVE-2024-4577                                           |      ✅      | Official Nuclei template.                               |   2024-06-11   |
| CVE-2024-4358                                           |      ✅      | Official Nuclei template.                               |   2024-06-11   |
| CVE-2024-37383                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-06-07   |
| CVE-2024-28995                                          |      ✅      | Official Nuclei template.                               |   2024-06-06   |
| CVE-2024-23692                                          |      ✅      | Official Nuclei template.                               |   2024-05-31   |
| CVE-2024-29824                                          |      ✅      | Official Nuclei template.                               |   2024-05-31   |
| CVE-2024-37032                                          |      ✅      | Official Nuclei template.                               |   2024-05-31   |
| CVE-2024-34470                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-05-29   |
| CVE-2017-3506                                           |      ✅      | Official Nuclei template.                               |   2024-05-28   |
| CVE-2024-24919                                          |      ✅      | Official Nuclei template.                               |   2024-05-28   |
| CVE-2022-5315                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-05-24   |
| CVE-2024-4985                                           |      ❌      | Not enough technical details available.                 |   2024-05-20   |
| CVE-2024-4956                                           |      ✅      | Official Nuclei template.                               |   2024-05-16   |
| CVE-2024-29895                                          |      ✅      | Official Nuclei template.                               |   2024-05-14   |
| CVE-2024-32113                                          |      ❌      | Not reproducible.                                       |   2024-05-08   |
| CVE-2024-4439                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-05-03   |
| CVE-2024-33544                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-29   |
| CVE-2024-32764                                          |      ❌      | Not enough technical details available.                 |   2024-04-26   |
| CVE-2024-28890                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-23   |
| CVE-2024-4040                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-22   |
| CVE-2024-27348                                          |      ✅      | Official Nuclei template.                               |   2024-04-22   |
| CVE-2024-26331                                          |      ✅      | Official Nuclei template.                               |   2024-04-13   |
| CVE-2024-3400                                           |      ✅      | Official Nuclei template.                               |   2024-04-12   |
| CVE-2024-24809                                          |      ✅      | Official Nuclei template.                               |   2024-04-10   |
| CVE-2024-31982                                          |      ✅      | Official Nuclei template.                               |   2024-04-10   |
| CVE-2024-29269                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-10   |
| CVE-2024-31461                                          |      ❌      | Requires authentication & integration with Jira.        |   2024-04-10   |
| CVE-2024-31849                                          |      ✅      | Official Nuclei template.                               |   2024-04-05   |
| CVE-2024-3273                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-03   |
| CVE-2024-2879                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-04-03   |
| CVE-2024-2389                                           |      ✅      | Official Nuclei template.                               |   2024-04-02   |
| CVE-2023-50969                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-28   |
| CVE-2023-24955                                          |      ❌      | Requires a valid SharePoint user.                       |   2024-03-26   |
| CVE-2023-48788                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-25   |
| CVE-2021-44529                                          |      ✅      | Official Nuclei template.                               |   2024-03-25   |
| CVE-2019-7256                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-03-25   |
| CVE-2024-29059                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2024-03-22   |
| CVE-2024-27956                                          |      ✅      | Official Nuclei template (modified by Ostorlab).        |   2024-03-21   |
| CVE-2024-23334                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-19   |
| CVE-2024-20767                                          |      ✅      | Official Nuclei template (modified by Ostorlab).        |   2024-03-18   |
| CVE-2024-28255                                          |      ✅      | Official Nuclei template.                               |   2024-03-15   |
| CVE-2024-2194                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-13   |
| CVE-2024-29973                                          |      ✅      | Official Nuclei template.                               |   2024-03-06   |
| CVE-2021-36380                                          |      ✅      | Official Nuclei template.                               |   2024-03-05   |
| CVE-2024-27198                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-05   |
| CVE-2024-0692                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-01   |
| CVE-2024-27497                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-03-01   |
| CVE-2023-29360                                          |      ❌      | Not remotely exploitable.                               |   2024-02-29   |
| CVE-2024-1212                                           |      ✅      | Official Nuclei template.                               |   2024-02-21   |
| CVE-2024-23113                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-02-15   |
| CVE-2024-1709                                           |      ✅      | Official Nuclei template.                               |   2024-02-15   |
| CVE-2024-21413                                          |      ❌      | Requires user interaction.                              |   2024-02-15   |
| CVE-2023-43770                                          |      ✅      | Custom Check by Ostorlab: included in Agent Asteroid.   |   2024-02-12   |
| CVE-2024-21762                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-02-09   |
| CVE-2024-22024                                          |      ✅      | Official Nuclei template.                               |   2024-02-08   |
| CVE-2024-23917                                          |      ✅      | Official Nuclei template.                               |   2024-02-06   |
| CVE-2024-21893                                          |      ✅      | Official Nuclei template.                               |   2024-01-31   |
| CVE-2024-21733                                          |      ✅      | Version check: included in Agent Asteroid.              |   2024-01-29   |
| CVE-2024-21620                                          |      ❌      | Not enough technical details available.                 |   2024-01-25   |
| CVE-2024-21619                                          |      ❌      | Not enough technical details available.                 |   2024-01-25   |
| CVE-2023-52251                                          |      ✅      | Official Nuclei template.                               |   2024-01-25   |
| CVE-2024-23897                                          |      ✅      | Official Nuclei template.                               |   2024-01-24   |
| CVE-2024-0204                                           |      ✅      | Official Nuclei template.                               |   2024-01-22   |
| CVE-2024-22233                                          |      ❌      | Not enough technical details available.                 |   2024-01-22   |
| CVE-2023-6548                                           |      ❌      | Requires authentication.                                |   2024-01-17   |
| CVE-2023-6549                                           |      ❌      | Not enough technical details available.                 |   2024-01-17   |
| CVE-2024-0519                                           |      ❌      | Target needs to open a specially crafted HTML page.     |   2024-01-17   |
| CVE-2023-7028                                           |      ✅      | Official Nuclei template.                               |   2024-01-12   |
| CVE-2018-15133                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-01-16   |
| CVE-2023-22527                                          |      ✅      | Nuclei template (tweaked by Ostorlab).                  |   2024-01-16   |
| CVE-2023-46805                                          |      ✅      | Official Nuclei template.                               |   2024-01-12   |
| CVE-2024-21887                                          |      ✅      | Official Nuclei template.                               |   2024-01-12   |
| CVE-2022-48618                                          |      ❌      | Not remotely exploitable.                               |   2024-01-09   |
| CVE-2023-51467                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2023-12-26   |
| CVE-2023-7102                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2023-12-24   |
| CVE-2023-7101                                           |      ❌      | Context dependent library vulnerability.                |   2023-12-24   |
| CVE-2023-7024                                           |      ❌      | User interaction needed.                                |   2023-12-21   |
| CVE-2023-6553                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2023-12-15   |
| CVE-2023-47565                                          |      ✅      | Official Nuclei template.                               |   2023-12-08   |
| CVE-2023-49897                                          |      ⏳      |                                                         |   2023-12-06   |
| CVE-2023-6448                                           |      ❌      | Not enough technical details available.                 |   2023-12-05   |
| CVE-2023-49070                                          |      ✅      | Official Nuclei template.                               |   2023-12-05   |
| CVE-2023-33063                                          |      ❌      | Out of scope: chipset vulnerability.                    |   2023-12-04   |
| CVE-2023-33106                                          |      ❌      | Out of scope: chipset vulnerability.                    |   2023-12-04   |
| CVE-2023-33107                                          |      ❌      | Out of scope: chipset vulnerability.                    |   2023-12-04   |
| CVE-2023-42916                                          |      ❌      | Not enough technical details available.                 |   2023-11-30   |
| CVE-2023-42917                                          |      ❌      | Not enough technical details available.                 |   2023-11-30   |
| CVE-2023-6345                                           |      ❌      | Not enough technical details available.                 |   2023-11-29   |
| CVE-2023-49103                                          |      ✅      | Official Nuclei template.                               |   2023-11-21   |
| CVE-2023-43177                                          |      ✅      | Official Nuclei template.                               |   2023-11-17   |
| CVE-2023-36036                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-11-14   |
| CVE-2023-36025                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-11-14   |
| CVE-2023-36033                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-11-14   |
| CVE-2023-47246                                          |      ✅      | Official Nuclei template.                               |   2023-11-10   |
| CVE-2023-22518                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-10-31   |
| CVE-2023-46604                                          |      ✅      | Official Nuclei template.                               |   2023-10-27   |
| CVE-2023-46747                                          |      ✅      | Official Nuclei template.                               |   2023-10-26   |
| CVE-2023-43208                                          |      ✅      | Official Nuclei template.                               |   2023-10-26   |
| CVE-2023-46748                                          |      ❌      | Requires authentication.                                |   2023-10-26   |
| CVE-2023-20273                                          |      ✅      | Metasploit module.                                      |   2023-10-25   |
| CVE-2023-45727                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-10-18   |
| CVE-2023-5631                                           |      ❌      | Requires user interaction.                              |   2023-10-18   |
| CVE-2023-20198                                          |      ✅      | Official Nuclei template.                               |   2023-10-16   |
| CVE-2023-44487                                          |      ❌      | Detection is not conclusive.                            |   2023-10-10   |
| CVE-2023-4966                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2023-10-10   |
| CVE-2023-36563                                          |      ❌      | Local attack vector.                                    |   2023-10-10   |
| CVE-2023-36584                                          |      ❌      | Local attack vector.                                    |   2023-10-10   |
| CVE-2023-41763                                          |      ❌      | Local attack vector.                                    |   2023-10-10   |
| CVE-2023-42824                                          |      ❌      | Local attack vector.                                    |   2023-10-04   |
| CVE-2023-22515                                          |      ✅      | Metasploit module.                                      |   2023-10-04   |
| CVE-2023-4911                                           |      ❌      | Local exploit.                                          |   2023-10-03   |
| CVE-2023-4211                                           |      ❌      | Local attack vector.                                    |   2023-10-01   |
| CVE-2023-5217                                           |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-09-28   |
| CVE-2023-36851                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-09-27   |
| CVE-2023-20109                                          |      ❌      | Requires authentication.                                |   2023-09-27   |
| CVE-2023-40044                                          |      ✅      | Metasploit module.                                      |   2023-09-27   |
| CVE-2023-41991                                          |      ❌      | Local attack vector.                                    |   2023-09-21   |
| CVE-2023-41993                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-09-21   |
| CVE-2023-41992                                          |      ❌      | Local attack vector.                                    |   2023-09-21   |
| CVE-2023-41179                                          |      ❌      | Requires authentication.                                |   2023-09-19   |
| CVE-2023-42793                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2023-09-19   |
| CVE-2023-38205                                          |      ✅      | Official Nuclei template.                               |   2023-09-14   |
| CVE-2023-26369                                          |      ❌      | Target needs to open a malicious file.                  |   2023-09-13   |
| CVE-2023-36802                                          |      ❌      | Local attack vector.                                    |   2023-09-12   |
| CVE-2023-36761                                          |      ❌      | Local attack vector.                                    |   2023-09-12   |
| CVE-2023-4863                                           |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-09-12   |
| CVE-2023-35674                                          |      ❌      | Local attack vector.                                    |   2023-09-11   |
| CVE-2023-41990                                          |      ❌      | Requires a malicious font file.                         |   2023-09-11   |
| CVE-2023-41064                                          |      ❌      | Requires a malicious image file.                        |   2023-09-07   |
| CVE-2023-41061                                          |      ❌      | Requires a malicious attachment file.                   |   2023-09-07   |
| CVE-2023-20269                                          |      ❌      | Requires bruteforce.                                    |   2023-09-06   |
| CVE-2023-4762                                           |      ❌      | Requires user interaction.                              |   2023-09-05   |
| CVE-2023-41265                                          |      ✅      | Same Nuclei template as CVE-2023-41266.                 |   2023-08-29   |
| CVE-2023-41266                                          |      ✅      | Official Nuclei template.                               |   2023-08-29   |
| CVE-2023-38831                                          |      ❌      | Requires a malicious archive file.                      |   2023-08-23   |
| CVE-2023-38035                                          |      ✅      | Official Nuclei template.                               |   2023-08-21   |
| CVE-2023-36847                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-08-17   |
| CVE-2023-36846                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-08-17   |
| CVE-2023-36845                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-08-17   |
| CVE-2023-36844                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-08-17   |
| CVE-2023-35082                                          |      ✅      | Official Nuclei template.                               |   2023-08-15   |
| CVE-2023-38180                                          |      ❌      | Exploit behavior not consistent.                        |   2023-08-08   |
| CVE-2023-35081                                          |      ❌      | Requires authentication.                                |   2023-08-03   |
| CVE-2023-37580                                          |      ✅      | Official Nuclei template.                               |   2023-07-31   |
| CVE-2023-37450                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-07-26   |
| CVE-2023-38606                                          |      ❌      | Local attack vector.                                    |   2023-07-26   |
| CVE-2023-35078                                          |      ✅      | Official Nuclei template.                               |   2023-07-25   |
| CVE-2023-38646                                          |      ✅      | Covered by tsunami scanner.                             |   2023-07-21   |
| CVE-2023-38203                                          |      ⏳      |                                                         |   2023-07-20   |
| CVE-2023-3519                                           |      ✅      | Metasploit module.                                      |   2023-07-19   |
| CVE-2023-29298                                          |      ✅      | Official Nuclei template.                               |   2023-07-12   |
| CVE-2023-29300                                          |      ✅      | Official Nuclei template.                               |   2023-07-12   |
| CVE-2023-35311                                          |      ❌      | Requires user interaction.                              |   2023-07-11   |
| CVE-2023-36874                                          |      ❌      | Local attack vector.                                    |   2023-07-11   |
| CVE-2023-36884                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-07-11   |
| CVE-2023-32049                                          |      ❌      | Requires user interaction.                              |   2023-07-11   |
| CVE-2023-32046                                          |      ❌      | Local attack vector.                                    |   2023-07-11   |
| CVE-2023-24489                                          |      ✅      | Official Nuclei template.                               |   2023-07-10   |
| CVE-2023-28204                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-06-23   |
| CVE-2023-32435                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-06-23   |
| CVE-2023-32409                                          |      ❌      | Local attack vector.                                    |   2023-06-23   |
| CVE-2023-32439                                          |      ❌      | Target needs to open a specially crafted HTML page.     |   2023-06-23   |
| CVE-2023-32434                                          |      ❌      | Local attack vector.                                    |   2023-06-23   |
| CVE-2023-32373                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-06-23   |
| CVE-2023-27992                                          |      ❌      | Missing public exploit.                                 |   2023-06-19   |
| CVE-2023-27997                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-06-13   |
| CVE-2023-20867                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-06-13   |
| CVE-2023-29357                                          |      ✅      | Official Nuclei template.                               |   2023-06-13   |
| CVE-2023-20887                                          |      ✅      | Official Nuclei template.                               |   2023-06-07   |
| CVE-2023-3079                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-06-05   |
| CVE-2023-34362                                          |      ✅      | Official Nuclei template.                               |   2023-06-02   |
| CVE-2023-32315                                          |      ✅      | Official Nuclei template.                               |   2023-05-26   |
| CVE-2023-2868                                           |      ❌      | Call back needed .                                      |   2023-05-24   |
| CVE-2023-33246                                          |      ✅      | Official Nuclei template.                               |   2023-05-24   |
| CVE-2023-33010                                          |      ❌      | Missing public exploit.                                 |   2023-05-24   |
| CVE-2023-33009                                          |      ❌      | Missing public exploit.                                 |   2023-05-24   |
| CVE-2023-2780                                           |      ✅      | Official Nuclei template.                               |   2023-05-17   |
| CVE-2023-29336                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-05-09   |
| CVE-2023-21492                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-05-04   |
| CVE-2023-2356                                           |      ✅      | Official Nuclei template.                               |   2023-04-27   |
| CVE-2023-29552                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-25   |
| CVE-2023-28771                                          |      ❌      | Metasploit module without a check/check_code.           |   2023-04-24   |
| CVE-2023-27524                                          |      ✅      | Official Nuclei template.                               |   2023-04-24   |
| CVE-2023-27350                                          |      ✅      | Official Nuclei template.                               |   2023-04-20   |
| CVE-2023-2136                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-19   |
| CVE-2023-2033                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-14   |
| CVE-2023-28252                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-11   |
| CVE-2023-28229                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-11   |
| CVE-2023-29492                                          |      ❌      | Missing public exploit.                                 |   2023-04-11   |
| CVE-2023-28205                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-10   |
| CVE-2023-28206                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-10   |
| CVE-2023-26083                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-04-06   |
| CVE-2023-1671                                           |      ✅      | Official Nuclei template.                               |   2023-04-04   |
| CVE-2023-20963                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-24   |
| CVE-2022-42948                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-24   |
| CVE-2023-26360                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2023-03-23   |
| CVE-2023-26359                                          |      ✅      | Same nuclei template as CVE-2023-26360                  |   2023-03-23   |
| CVE-2023-28434                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-22   |
| CVE-2023-28432                                          |      ✅      | Official Nuclei template.                               |   2023-03-22   |
| CVE-2023-28461                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2023-03-15   |
| CVE-2023-25280                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-03-15   |
| CVE-2023-1389                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2023-03-15   |
| CVE-2023-24880                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-14   |
| CVE-2023-23397                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-14   |
| CVE-2023-27532                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-10   |
| CVE-2022-41328                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-07   |
| CVE-2019-8720                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-03-06   |
| CVE-2022-43939                                          |      ✅      | Custom Nuclei template.                                 |   2023-03-04   |
| CVE-2023-23529                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-02-27   |
| CVE-2022-47986                                          |      ✅      | Official Nuclei template.                               |   2023-02-17   |
| CVE-2023-23752                                          |      ✅      | Official Nuclei template.                               |   2023-02-16   |
| CVE-2023-21823                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-02-14   |
| CVE-2023-21715                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-02-14   |
| CVE-2023-23376                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-02-14   |
| CVE-2023-25717                                          |      ✅      | Official Nuclei template.                               |   2023-02-13   |
| CVE-2022-24990                                          |      ✅      | Official Nuclei template.                               |   2023-02-07   |
| CVE-2023-0669                                           |      ✅      | Official Nuclei template.                               |   2023-02-06   |
| CVE-2023-0266                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-01-30   |
| CVE-2023-21608                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-01-18   |
| CVE-2022-47966                                          |      ✅      | Official Nuclei template.                               |   2023-01-18   |
| CVE-2023-21839                                          |      ✅      | Metasploit module.                                      |   2023-01-17   |
| CVE-2023-22952                                          |      ❌      | Metasploit module without a check/check_code.           |   2023-01-11   |
| CVE-2023-21674                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2023-01-10   |
| CVE-2022-44877                                          |      ✅      | Official Nuclei template.                               |   2023-01-05   |
| CVE-2022-42475                                          |      ❌      | Memory corruption and needs a ROP chain.                |   2023-01-02   |
| CVE-2022-47945                                          |      ✅      | Official Nuclei template.                               |   2022-12-23   |
| CVE-2022-26485                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-12-22   |
| CVE-2022-26486                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-12-22   |
| CVE-2022-42856                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-12-15   |
| CVE-2022-44698                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-12-13   |
| CVE-2022-27518                                          |      ❌      | Missing public exploit.                                 |   2022-12-13   |
| CVE-2022-46169                                          |      ✅      | Official Nuclei template.                               |   2022-12-05   |
| CVE-2022-4262                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-12-02   |
| CVE-2022-4135                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-24   |
| CVE-2022-41223                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-21   |
| CVE-2022-40765                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-21   |
| CVE-2022-41128                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-41125                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-41091                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-41080                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-41073                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-41049                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-09   |
| CVE-2022-31199                                          |      ❌      | Missing public exploit.                                 |   2022-11-07   |
| CVE-2022-3723                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-01   |
| CVE-2022-42827                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-11-01   |
| CVE-2022-38181                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-10-25   |
| CVE-2016-20017                                          |      ✅      | Metasploit module.                                      |   2022-10-19   |
| CVE-2022-40684                                          |      ✅      | Official Nuclei template.                               |   2022-10-18   |
| CVE-2022-21587                                          |      ✅      | Official Nuclei template.                               |   2022-10-18   |
| CVE-2022-41033                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-10-11   |
| CVE-2022-41040                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-10-02   |
| CVE-2022-41082                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-10-02   |
| CVE-2022-2856                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-26   |
| CVE-2022-3038                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-26   |
| CVE-2022-3075                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-26   |
| CVE-2022-41352                                          |      ❌      | Metasploit module without a check/check_code.           |   2022-09-25   |
| CVE-2022-3236                                           |      ❌      | Missing public exploit.                                 |   2022-09-23   |
| CVE-2022-39197                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-21   |
| CVE-2022-32917                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-20   |
| CVE-2022-35914                                          |      ✅      | Official Nuclei template.                               |   2022-09-19   |
| CVE-2022-40139                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-19   |
| CVE-2022-37969                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-09-13   |
| CVE-2022-27593                                          |      ✅      | Official Nuclei template.                               |   2022-09-08   |
| CVE-2022-31814                                          |      ✅      | Official Nuclei template.                               |   2022-09-05   |
| CVE-2022-36537                                          |      ✅      | Official Nuclei template.                               |   2022-08-26   |
| CVE-2022-36804                                          |      ✅      | Official Nuclei template.                               |   2022-08-25   |
| CVE-2022-32894                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-08-24   |
| CVE-2022-32893                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-08-24   |
| CVE-2022-37042                                          |      ✅      | Official Nuclei template.                               |   2022-08-12   |
| CVE-2022-0028                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-08-10   |
| CVE-2022-34713                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-08-09   |
| CVE-2022-2294                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-07-27   |
| CVE-2022-1364                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-07-26   |
| CVE-2022-1096                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-07-22   |
| CVE-2022-26138                                          |      ✅      | Official Nuclei template.                               |   2022-07-20   |
| CVE-2022-35405                                          |      ✅      | Official Nuclei template.                               |   2022-07-19   |
| CVE-2022-33891                                          |      ✅      | Official Nuclei template.                               |   2022-07-18   |
| CVE-2022-26352                                          |      ✅      | Official Nuclei template.                               |   2022-07-17   |
| CVE-2022-22047                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-07-12   |
| CVE-2022-22071                                          |      ❌      | Out of scope: chipset vulnerability.                    |   2022-06-14   |
| CVE-2022-26134                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-06-03   |
| CVE-2022-30190                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-06-01   |
| CVE-2022-20821                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2022-05-26   |
| CVE-2022-22674                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-05-26   |
| CVE-2022-22675                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-05-26   |
| CVE-2022-28958                                          |      ❌      | Fake vulnerability.                                     |   2022-05-18   |
| CVE-2022-29303                                          |      ✅      | Official Nuclei template.                               |   2022-05-12   |
| CVE-2022-30525                                          |      ✅      | Official Nuclei template.                               |   2022-05-12   |
| CVE-2022-26923                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-05-10   |
| CVE-2022-26925                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-05-10   |
| CVE-2022-30333                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-05-09   |
| CVE-2022-1388                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-05-05   |
| CVE-2022-24706                                          |      ✅      | Official Nuclei template.                               |   2022-04-26   |
| CVE-2022-29499                                          |      ✅      | Official Nuclei template.                               |   2022-04-25   |
| CVE-2022-27924                                          |      ❌      | Missing public exploit.                                 |   2022-04-20   |
| CVE-2022-27925                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-04-20   |
| CVE-2022-27926                                          |      ✅      | Official Nuclei template.                               |   2022-04-20   |
| CVE-2022-26133                                          |      ✅      | Covered by tsunami scanner.                             |   2022-04-20   |
| CVE-2022-21445                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2022-04-19   |
| CVE-2022-28810                                          |      ✅      | Metasploit module.                                      |   2022-04-18   |
| CVE-2022-29464                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-04-18   |
| CVE-2022-24521                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-04-15   |
| CVE-2022-26904                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-04-15   |
| CVE-2022-22960                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-04-13   |
| CVE-2022-22954                                          |      ✅      | Official Nuclei template.                               |   2022-04-11   |
| CVE-2022-0609                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-04-04   |
| CVE-2022-22963                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-04-01   |
| CVE-2022-22965                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-04-01   |
| CVE-2022-26871                                          |      ❌      | Not enough technical details available.                 |   2022-03-29   |
| CVE-2022-26258                                          |      ❌      | Authentication Required .                               |   2022-03-27   |
| CVE-2022-1040                                           |      ✅      | Official Nuclei template.                               |   2022-03-25   |
| CVE-2022-22620                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-18   |
| CVE-2022-22587                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-18   |
| CVE-2022-26500                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-17   |
| CVE-2022-26501                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-17   |
| CVE-2021-39793                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-16   |
| CVE-2022-0847                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-10   |
| CVE-2022-26143                                          |      ❌      | DOS attack.                                             |   2022-03-10   |
| CVE-2022-0412                                           |      ✅      | Official Nuclei template.                               |   2022-03-08   |
| CVE-2022-26318                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2022-03-04   |
| CVE-2022-22706                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-03-03   |
| CVE-2022-22947                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-03-03   |
| CVE-2022-23176                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-24   |
| CVE-2022-0543                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-18   |
| CVE-2021-45382                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2022-02-17   |
| CVE-2021-3560                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-16   |
| CVE-2022-24086                                          |      ❌      | Missing public exploit.                                 |   2022-02-16   |
| CVE-2022-24112                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2022-02-11   |
| CVE-2021-4102                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-11   |
| CVE-2022-20701                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-10   |
| CVE-2022-20699                                          |      ✅      | Metasploit module.                                      |   2022-02-10   |
| CVE-2022-20703                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-10   |
| CVE-2022-20708                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-10   |
| CVE-2022-20700                                          |      ❌      | Missing public exploit.                                 |   2022-02-10   |
| CVE-2022-22536                                          |      ✅      | Official Nuclei template.                               |   2022-02-09   |
| CVE-2022-21971                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-09   |
| CVE-2022-22718                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-09   |
| CVE-2022-21999                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-09   |
| CVE-2022-24682                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-02-08   |
| CVE-2021-4034                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-28   |
| CVE-2021-22600                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-26   |
| CVE-2021-35587                                          |      ✅      | Official Nuclei template.                               |   2022-01-19   |
| CVE-2022-23131                                          |      ✅      | Official Nuclei template.                               |   2022-01-13   |
| CVE-2022-23134                                          |      ✅      | Official Nuclei template.                               |   2022-01-13   |
| CVE-2022-21882                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-11   |
| CVE-2022-21919                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-11   |
| CVE-2021-35247                                          |      ❌      | Missing public exploit.                                 |   2022-01-10   |
| CVE-2022-22265                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-10   |
| CVE-2021-44168                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2022-01-04   |
| CVE-2021-43890                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-12-15   |
| CVE-2021-0920                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-12-15   |
| CVE-2021-1048                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-12-15   |
| CVE-2021-45046                                          |      ✅      | Official Nuclei template.                               |   2021-12-14   |
| CVE-2021-44515                                          |      ✅      | Official Nuclei template.                               |   2021-12-12   |
| CVE-2021-44228                                          |      ✅      | Official Nuclei template.                               |   2021-12-10   |
| CVE-2021-20038                                          |      ✅      | Official Nuclei template.                               |   2021-12-08   |
| CVE-2021-27860                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-12-08   |
| CVE-2021-43798                                          |      ✅      | Covered by tsunami scanner.                             |   2021-12-07   |
| CVE-2021-44077                                          |      ✅      | Official Nuclei template.                               |   2021-11-28   |
| CVE-2021-38000                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-23   |
| CVE-2021-38003                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-23   |
| CVE-2021-44026                                          |      ❌      | Missing public exploit.                                 |   2021-11-18   |
| CVE-2021-41277                                          |      ✅      | Covered by tsunami scanner.                             |   2021-11-17   |
| CVE-2021-41379                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-09   |
| CVE-2021-42278                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-09   |
| CVE-2021-42321                                          |      ❌      | Required credentials.                                   |   2021-11-09   |
| CVE-2021-42292                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-09   |
| CVE-2021-42287                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-11-09   |
| CVE-2021-42237                                          |      ✅      | Official Nuclei template.                               |   2021-11-05   |
| CVE-2021-42258                                          |      ✅      | Official Nuclei template.                               |   2021-10-22   |
| CVE-2021-30807                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-19   |
| CVE-2021-27561                                          |      ✅      | Official Nuclei template.                               |   2021-10-15   |
| CVE-2021-20124                                          |      ✅      | Official Nuclei template.                               |   2021-10-13   |
| CVE-2021-20123                                          |      ✅      | Official Nuclei template.                               |   2021-10-13   |
| CVE-2021-41357                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-12   |
| CVE-2021-40449                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-12   |
| CVE-2021-40450                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-12   |
| CVE-2021-30633                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-08   |
| CVE-2021-30632                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-08   |
| CVE-2021-37976                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-08   |
| CVE-2021-37975                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-08   |
| CVE-2021-37973                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-08   |
| CVE-2021-42013                                          |      ✅      | Official Nuclei template.                               |   2021-10-07   |
| CVE-2021-25487                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-06   |
| CVE-2021-25489                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-10-06   |
| CVE-2021-39226                                          |      ✅      | Official Nuclei template.                               |   2021-10-05   |
| CVE-2021-41773                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-10-05   |
| CVE-2021-40655                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2021-09-24   |
| CVE-2021-22005                                          |      ✅      | Official Nuclei template.                               |   2021-09-23   |
| CVE-2021-22941                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2021-09-23   |
| CVE-2021-22017                                          |      ❌      | Missing public exploit.                                 |   2021-09-23   |
| CVE-2021-36260                                          |      ✅      | Official Nuclei template.                               |   2021-09-22   |
| CVE-2021-38406                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-17   |
| CVE-2021-40438                                          |      ✅      | Official Nuclei template.                               |   2021-09-16   |
| CVE-2121-33044                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2021-09-15   |
| CVE-2021-40444                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-38649                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-36955                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-38647                                          |      ✅      | Official Nuclei template.                               |   2021-09-15   |
| CVE-2021-38648                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-38645                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-38646                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-15   |
| CVE-2021-38163                                          |      ❌      | Required credentials.                                   |   2021-09-14   |
| CVE-2021-40870                                          |      ✅      | Official Nuclei template.                               |   2021-09-13   |
| CVE-2021-30657                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30666                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30713                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30761                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30762                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30661                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30663                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-30665                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-08   |
| CVE-2021-40539                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-09-07   |
| CVE-2021-28550                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-09-02   |
| CVE-2021-37415                                          |      ❌      | Missing public exploit.                                 |   2021-09-01   |
| CVE-2021-26084                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-08-30   |
| CVE-2021-32648                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2021-08-26   |
| CVE-2021-30883                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-30983                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-30858                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-30860                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-30869                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-30900                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-31010                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-24   |
| CVE-2021-39144                                          |      ✅      | Official Nuclei template.                               |   2021-08-23   |
| CVE-2021-35395                                          |      ❌      | Missing public exploit.                                 |   2021-08-16   |
| CVE-2021-35394                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-16   |
| CVE-2021-26086                                          |      ✅      | Official Nuclei template.                               |   2021-08-15   |
| CVE-2021-34486                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-12   |
| CVE-2021-34484                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-12   |
| CVE-2021-36942                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-12   |
| CVE-2021-36948                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-12   |
| CVE-2021-20028                                          |      ❌      | Missing public exploit.                                 |   2021-08-04   |
| CVE-2021-30563                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-08-03   |
| CVE-2021-26085                                          |      ✅      | Official Nuclei template.                               |   2021-08-02   |
| CVE-2021-36742                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-29   |
| CVE-2021-36741                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-29   |
| CVE-2021-36934                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-22   |
| CVE-2021-35464                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-07-22   |
| CVE-2021-34448                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-16   |
| CVE-2021-34473                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-14   |
| CVE-2021-33771                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-14   |
| CVE-2021-33766                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-14   |
| CVE-2021-34523                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-14   |
| CVE-2021-31979                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-14   |
| CVE-2021-35211                                          |      ❌      | Missing public exploit.                                 |   2021-07-14   |
| CVE-2021-30116                                          |      ❌      | Missing public exploit.                                 |   2021-07-09   |
| CVE-2021-34527                                          |      ❌      | Unprivileged Authenticated or User interaction needed.  |   2021-07-02   |
| CVE-2021-30554                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-07-02   |
| CVE-2021-30551                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-15   |
| CVE-2021-25394                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-11   |
| CVE-2021-25395                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-11   |
| CVE-2020-11261                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-09   |
| CVE-2021-1675                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-31956                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-31199                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-33739                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-31955                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-33742                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-31201                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-08   |
| CVE-2021-30533                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-06-07   |
| CVE-2021-22894                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-27   |
| CVE-2021-22899                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-27   |
| CVE-2021-27852                                          |      ❌      | Not enough technical details available                  |   2021-05-27   |
| CVE-2021-22900                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-27   |
| CVE-2021-21985                                          |      ✅      | Official Nuclei template.                               |   2021-05-26   |
| CVE-2021-27562                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-25   |
| CVE-2021-29256                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-24   |
| CVE-2021-28799                                          |      ❌      | Missing public exploit.                                 |   2021-05-12   |
| CVE-2021-31166                                          |      ❌      | Metasploit module without a check/check_code.           |   2021-05-11   |
| CVE-2021-31207                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-11   |
| CVE-2021-28664                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-10   |
| CVE-2021-28663                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-10   |
| CVE-2021-1906                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-07   |
| CVE-2021-31755                                          |      ✅      | Official Nuclei template.                               |   2021-05-07   |
| CVE-2021-1905                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-07   |
| CVE-2021-1497                                           |      ✅      | Official Nuclei template.                               |   2021-05-06   |
| CVE-2021-1498                                           |      ✅      | Official Nuclei template.                               |   2021-05-06   |
| CVE-2021-21551                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-05-04   |
| CVE-2021-20090                                          |      ✅      | Official Nuclei template.                               |   2021-04-29   |
| CVE-2021-29441                                          |      ✅      | Covered by tsunami scanner.                             |   2021-04-27   |
| CVE-2021-21206                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-26   |
| CVE-2021-21224                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-26   |
| CVE-2021-21220                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-26   |
| CVE-2021-22204                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-23   |
| CVE-2021-22205                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-04-23   |
| CVE-2021-22893                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-23   |
| CVE-2021-20023                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-20   |
| CVE-2021-3493                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-17   |
| CVE-2020-2509                                           |      ❌      | Requires a MITM.                                        |   2021-04-17   |
| CVE-2021-28310                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-13   |
| CVE-2021-20021                                          |      ❌      | Missing public exploit.                                 |   2021-04-09   |
| CVE-2021-20022                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-09   |
| CVE-2021-1870                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-02   |
| CVE-2021-1879                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-02   |
| CVE-2021-1782                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-02   |
| CVE-2021-1871                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-02   |
| CVE-2021-1789                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-04-02   |
| CVE-2021-21975                                          |      ✅      | Official Nuclei template.                               |   2021-03-31   |
| CVE-2021-22986                                          |      ✅      | Official Nuclei template.                               |   2021-03-31   |
| CVE-2021-22991                                          |      ❌      | Missing public exploit.                                 |   2021-03-31   |
| CVE-2021-22506                                          |      ❌      | Missing public exploit.                                 |   2021-03-26   |
| CVE-2021-25372                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-26   |
| CVE-2021-25371                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-26   |
| CVE-2021-25370                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-26   |
| CVE-2021-25369                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-26   |
| CVE-2021-21193                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-16   |
| CVE-2021-26411                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-11   |
| CVE-2021-27085                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-11   |
| CVE-2021-27059                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-11   |
| CVE-2021-21166                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-09   |
| CVE-2021-25337                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-04   |
| CVE-2021-27065                                          |      ✅      | Metasploit module.                                      |   2021-03-02   |
| CVE-2021-26858                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-02   |
| CVE-2021-26857                                          |      ✅      | Official Nuclei template.                               |   2021-03-02   |
| CVE-2021-26855                                          |      ✅      | Metasploit module.                                      |   2021-03-02   |
| CVE-2021-27876                                          |      ✅      | Metasploit module.                                      |   2021-03-01   |
| CVE-2021-27878                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-01   |
| CVE-2021-27877                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-03-01   |
| CVE-2021-1732                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-25   |
| CVE-2021-21972                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-02-24   |
| CVE-2021-21973                                          |      ✅      | Official Nuclei template.                               |   2021-02-24   |
| CVE-2021-27101                                          |      ❌      | Vulnerable environment requires commercial license.     |   2021-02-16   |
| CVE-2021-27102                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-16   |
| CVE-2021-21315                                          |      ✅      | Official Nuclei template.                               |   2021-02-16   |
| CVE-2021-27104                                          |      ❌      | Missing public exploit.                                 |   2021-02-16   |
| CVE-2021-27103                                          |      ❌      | Vulnerable environment requires commercial license.     |   2021-02-16   |
| CVE-2021-25297                                          |      ❌      | Authentication Required.                                |   2021-02-15   |
| CVE-2021-25296                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-15   |
| CVE-2021-25298                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-15   |
| CVE-2021-21017                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-11   |
| CVE-2021-23874                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-10   |
| CVE-2021-21148                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-02-09   |
| CVE-2021-22502                                          |      ✅      | Official Nuclei template.                               |   2021-02-08   |
| CVE-2021-20016                                          |      ❌      | Missing public exploit.                                 |   2021-02-04   |
| CVE-2020-2506                                           |      ❌      | Missing public exploit.                                 |   2021-02-03   |
| CVE-2020-25506                                          |      ✅      | Official Nuclei template.                               |   2021-02-02   |
| CVE-2020-29557                                          |      ✅      | Custom Nuclei template by Ostorlab.                     |   2021-01-29   |
| CVE-2021-25646                                          |      ✅      | Covered by tsunami scanner.                             |   2021-01-29   |
| CVE-2021-3156                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-26   |
| CVE-2021-3223                                           |      ✅      | Covered by tsunami scanner.                             |   2021-01-26   |
| CVE-2020-36193                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-18   |
| CVE-2020-6572                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-14   |
| CVE-2021-3129                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2021-01-12   |
| CVE-2021-1647                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-12   |
| CVE-2020-16017                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-08   |
| CVE-2020-16013                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2021-01-08   |
| CVE-2020-17519                                          |      ✅      | Covered by tsunami scanner.                             |   2021-01-05   |
| CVE-2020-10148                                          |      ✅      | Official Nuclei template.                               |   2020-12-29   |
| CVE-2020-35730                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-12-28   |
| CVE-2020-29583                                          |      ✅      | Official Nuclei template.                               |   2020-12-22   |
| CVE-2020-17530                                          |      ✅      | Official Nuclei template.                               |   2020-12-10   |
| CVE-2020-17144                                          |      ❌      | Required credentials.                                   |   2020-12-09   |
| CVE-2020-27930                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-12-08   |
| CVE-2020-27932                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-12-08   |
| CVE-2020-27950                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-12-08   |
| CVE-2020-4006                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-23   |
| CVE-2020-13671                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-20   |
| CVE-2020-28949                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-19   |
| CVE-2019-20933                                          |      ✅      | Covered by tsunami scanner.                             |   2020-11-18   |
| CVE-2020-17087                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-11   |
| CVE-2020-13927                                          |      ✅      | Official Nuclei template.                               |   2020-11-10   |
| CVE-2020-16846                                          |      ✅      | Official Nuclei template.                               |   2020-11-06   |
| CVE-2020-14750                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2020-11-02   |
| CVE-2020-16009                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-02   |
| CVE-2020-16010                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-02   |
| CVE-2020-15999                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-11-02   |
| CVE-2018-19953                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-28   |
| CVE-2020-8260                                           |      ❌      | Required credentials.                                   |   2020-10-28   |
| CVE-2018-19943                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-28   |
| CVE-2018-19949                                          |      ❌      | Missing public exploit.                                 |   2020-10-28   |
| CVE-2020-14882                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2020-10-21   |
| CVE-2020-14864                                          |      ✅      | Official Nuclei template.                               |   2020-10-21   |
| CVE-2020-14883                                          |      ✅      | Covered by tsunami scanner.                             |   2020-10-21   |
| CVE-2020-14871                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-21   |
| CVE-2020-3580                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-21   |
| CVE-2020-3992                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-20   |
| CVE-2020-9907                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-16   |
| CVE-2020-9934                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-10-16   |
| CVE-2020-5135                                           |      ❌      | Missing public exploit.                                 |   2020-10-12   |
| CVE-2020-26919                                          |      ✅      | Official Nuclei template.                               |   2020-10-09   |
| CVE-2020-8243                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-09-30   |
| CVE-2020-25223                                          |      ✅      | Official Nuclei template.                               |   2020-09-25   |
| CVE-2020-3569                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-09-22   |
| CVE-2020-0878                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-09-11   |
| CVE-2020-25213                                          |      ✅      | Official Nuclei template.                               |   2020-09-09   |
| CVE-2020-24557                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-09-01   |
| CVE-2020-3566                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-29   |
| CVE-2020-1464                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-17   |
| CVE-2020-1472                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-17   |
| CVE-2020-1380                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-17   |
| CVE-2020-3433                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-17   |
| CVE-2019-5591                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-08-14   |
| CVE-2020-17463                                          |      ✅      | Official Nuclei template.                               |   2020-08-13   |
| CVE-2020-17496                                          |      ✅      | Official Nuclei template.                               |   2020-08-12   |
| CVE-2020-8218                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-30   |
| CVE-2020-12812                                          |      ❌      | Missing public exploit.                                 |   2020-07-24   |
| CVE-2020-3452                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2020-07-22   |
| CVE-2020-11978                                          |      ✅      | Official Nuclei template.                               |   2020-07-16   |
| CVE-2020-14644                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2024-07-15   |
| CVE-2020-1040                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-14   |
| CVE-2020-1350                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-14   |
| CVE-2020-1147                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-14   |
| CVE-2020-6287                                           |      ✅      | Official Nuclei template.                               |   2020-07-14   |
| CVE-2020-10987                                          |      ❌      | Authentication Required.                                |   2020-07-13   |
| CVE-2020-8193                                           |      ✅      | Official Nuclei template.                               |   2020-07-10   |
| CVE-2020-8196                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-10   |
| CVE-2020-8195                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-10   |
| CVE-2020-9377                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-07-09   |
| CVE-2020-15505                                          |      ✅      | Official Nuclei template.                               |   2020-07-06   |
| CVE-2020-5902                                           |      ✅      | Official Nuclei template.                               |   2020-07-01   |
| CVE-2020-15415                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2020-06-30   |
| CVE-2020-2021                                           |      ❌      | Missing public exploit.                                 |   2020-06-29   |
| CVE-2020-11899                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-06-17   |
| CVE-2020-9819                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-06-09   |
| CVE-2020-9818                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-06-09   |
| CVE-2020-0986                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-06-09   |
| CVE-2020-9859                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-06-05   |
| CVE-2020-5410                                           |      ✅      | Official Nuclei template.                               |   2020-06-02   |
| CVE-2020-8816                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-05-29   |
| CVE-2020-1956                                           |      ✅      | Official Nuclei template.                               |   2020-05-22   |
| CVE-2020-1054                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-05-21   |
| CVE-2020-5741                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-05-08   |
| CVE-2020-4428                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-05-07   |
| CVE-2020-4430                                           |      ❌      | Metasploit module without a check/check_code.           |   2020-05-07   |
| CVE-2020-4427                                           |      ❌      | Metasploit module without a check/check_code.           |   2020-05-07   |
| CVE-2020-12641                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-05-04   |
| CVE-2020-1631                                           |      ❌      | Missing public exploit.                                 |   2020-05-04   |
| CVE-2020-11651                                          |      ❌      | Metasploit module without a check/check_code.           |   2020-04-30   |
| CVE-2020-11652                                          |      ❌      | Metasploit module without a check/check_code.           |   2020-04-30   |
| CVE-2020-12271                                          |      ❌      | Missing public exploit.                                 |   2020-04-27   |
| CVE-2020-6820                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-24   |
| CVE-2020-6819                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-24   |
| CVE-2020-0938                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-15   |
| CVE-2020-1020                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-15   |
| CVE-2020-1027                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-15   |
| CVE-2020-0968                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-15   |
| CVE-2020-3161                                           |      ❌      | DOS attack.                                             |   2020-04-15   |
| CVE-2020-11738                                          |      ✅      | Official Nuclei template.                               |   2020-04-13   |
| CVE-2020-3952                                           |      ✅      | Metasploit module.                                      |   2020-04-10   |
| CVE-2020-5735                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-04-08   |
| CVE-2020-10199                                          |      ✅      | Official Nuclei template.                               |   2020-04-01   |
| CVE-2020-5722                                           |      ✅      | Metasploit module.                                      |   2020-03-23   |
| CVE-2020-7961                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2020-03-20   |
| CVE-2020-3950                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-17   |
| CVE-2020-8468                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-17   |
| CVE-2020-8599                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-17   |
| CVE-2020-8467                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-17   |
| CVE-2020-5847                                           |      ✅      | Official Nuclei template.                               |   2020-03-16   |
| CVE-2020-5849                                           |      ✅      | Metasploit module.                                      |   2020-03-16   |
| CVE-2020-0787                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-12   |
| CVE-2020-0796                                           |      ✅      | Metasploit module.                                      |   2020-03-12   |
| CVE-2020-10181                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-11   |
| CVE-2020-0041                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-10   |
| CVE-2020-0069                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-10   |
| CVE-2020-6207                                           |      ✅      | Official Nuclei template.                               |   2020-03-10   |
| CVE-2016-11021                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-08   |
| CVE-2020-10221                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-08   |
| CVE-2020-10189                                          |      ✅      | Metasploit module.                                      |   2020-03-06   |
| CVE-2019-20500                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-05   |
| CVE-2020-9054                                           |      ✅      | Official Nuclei template.                               |   2020-03-04   |
| CVE-2019-17026                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-03-02   |
| CVE-2020-6418                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-27   |
| CVE-2020-3837                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-27   |
| CVE-2020-1938                                           |      ✅      | Metasploit module and Tsunami scanner were used.        |   2020-02-24   |
| CVE-2020-3153                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-19   |
| CVE-2020-0688                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-11   |
| CVE-2020-0674                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-11   |
| CVE-2020-0683                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-11   |
| CVE-2019-18988                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-07   |
| CVE-2019-19356                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-07   |
| CVE-2020-8657                                           |      ✅      | Metasploit module.                                      |   2020-02-06   |
| CVE-2020-8655                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-06   |
| CVE-2020-3118                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-02-05   |
| CVE-2020-8644                                           |      ✅      | Official Nuclei template.                               |   2020-02-05   |
| CVE-2020-8515                                           |      ✅      | Official Nuclei template.                               |   2020-02-01   |
| CVE-2020-7247                                           |      ❌      | Metasploit module without a check/check_code.           |   2020-01-29   |
| CVE-2019-18426                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-01-21   |
| CVE-2020-2551                                           |      ✅      | Custom Exploit by Ostorlab                              |   2020-01-15   |
| CVE-2020-2555                                           |      ✅      | Metasploit module.                                      |   2020-01-15   |
| CVE-2020-0638                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-01-14   |
| CVE-2020-0601                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-01-14   |
| CVE-2020-0646                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2020-01-14   |
| CVE-2019-17621                                          |      ❌      | Metasploit module without a check/check_code.           |   2019-12-30   |
| CVE-2019-17558                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2019-12-30   |
| CVE-2019-20085                                          |      ✅      | Official Nuclei template.                               |   2019-12-29   |
| CVE-2019-19781                                          |      ✅      | Official Nuclei template.                               |   2019-12-27   |
| CVE-2019-10758                                          |      ✅      | Official Nuclei template.                               |   2019-12-24   |
| CVE-2019-4716                                           |      ❌      | Metasploit module without a check/check_code.           |   2019-12-18   |
| CVE-2019-7287                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-18   |
| CVE-2019-8605                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-18   |
| CVE-2019-8526                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-18   |
| CVE-2019-8506                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-18   |
| CVE-2019-7483                                           |      ❌      | Missing public exploit.                                 |   2019-12-18   |
| CVE-2019-7286                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-18   |
| CVE-2019-7481                                           |      ✅      | Official Nuclei template.                               |   2019-12-17   |
| CVE-2019-18935                                          |      ✅      | Custom Nuclei template.                                 |   2019-12-11   |
| CVE-2019-1458                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-12-10   |
| CVE-2019-5544                                           |      ❌      | Missing public exploit.                                 |   2019-12-06   |
| CVE-2019-7192                                           |      ✅      | Official Nuclei template.                               |   2019-12-05   |
| CVE-2019-7193                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2019-12-05   |
| CVE-2019-7194                                           |      ✅      | Metasploit module.                                      |   2019-12-05   |
| CVE-2019-7195                                           |      ✅      | Metasploit module.                                      |   2019-12-05   |
| CVE-2019-5825                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-25   |
| CVE-2019-13720                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-25   |
| CVE-2019-15271                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-25   |
| CVE-2019-12409                                          |      ✅      | Covered by tsunami scanner.                             |   2019-11-18   |
| CVE-2019-1405                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-12   |
| CVE-2019-1429                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-12   |
| CVE-2019-1388                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-12   |
| CVE-2019-1385                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-11-12   |
| CVE-2019-18187                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-10-28   |
| CVE-2019-11043                                          |      ✅      | Metasploit module.                                      |   2019-10-28   |
| CVE-2019-3010                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-10-16   |
| CVE-2019-16278                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2019-10-14   |
| CVE-2019-2215                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-10-11   |
| CVE-2019-1322                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-10-10   |
| CVE-2019-1315                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-10-10   |
| CVE-2019-16928                                          |      ❌      | Missing public exploit.                                 |   2019-09-27   |
| CVE-2019-16920                                          |      ✅      | Official Nuclei template.                               |   2019-09-27   |
| CVE-2019-16759                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2019-09-24   |
| CVE-2019-1367                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-23   |
| CVE-2019-16057                                          |      ✅      | Official Nuclei template.                               |   2019-09-16   |
| CVE-2019-16256                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-12   |
| CVE-2019-1253                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-11   |
| CVE-2019-1297                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-11   |
| CVE-2019-1215                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-11   |
| CVE-2019-1214                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-11   |
| CVE-2019-15949                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-09-05   |
| CVE-2019-13608                                          |      ❌      | Missing public exploit.                                 |   2019-08-29   |
| CVE-2019-15752                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-08-28   |
| CVE-2019-15107                                          |      ✅      | Official Nuclei template.                               |   2019-08-15   |
| CVE-2019-11581                                          |      ✅      | Official Nuclei template.                               |   2019-08-09   |
| CVE-2019-0193                                           |      ✅      | Official Nuclei template.                               |   2019-08-01   |
| CVE-2019-11707                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-23   |
| CVE-2019-11708                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-23   |
| CVE-2019-1579                                           |      ❌      | Exploit is version dependent.                           |   2019-07-19   |
| CVE-2019-13272                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-17   |
| CVE-2019-12991                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2019-07-16   |
| CVE-2019-12989                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2019-07-16   |
| CVE-2019-1132                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-15   |
| CVE-2019-1130                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-15   |
| CVE-2019-0880                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-15   |
| CVE-2019-1129                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-07-15   |
| CVE-2018-15811                                          |      ❌      | Metasploit module without a check/check_code.           |   2019-07-03   |
| CVE-2018-18325                                          |      ❌      | Metasploit module without a check/check_code.           |   2019-07-03   |
| CVE-2019-5786                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-06-27   |
| CVE-2019-1064                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-06-12   |
| CVE-2019-1069                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-06-12   |
| CVE-2010-5330                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-06-11   |
| CVE-2019-10149                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-06-05   |
| CVE-2018-13382                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2019-06-04   |
| CVE-2018-13379                                          |      ✅      | Official Nuclei template.                               |   2019-06-04   |
| CVE-2019-11580                                          |      ✅      | Official Nuclei template.                               |   2019-06-03   |
| CVE-2018-13383                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-05-29   |
| CVE-2019-9670                                           |      ✅      | Official Nuclei template.                               |   2019-05-29   |
| CVE-2018-7841                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2019-05-22   |
| CVE-2019-11634                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-05-22   |
| CVE-2019-0903                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-05-16   |
| CVE-2019-0863                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-05-16   |
| CVE-2019-0708                                           |      ✅      | Metasploit module.                                      |   2019-05-16   |
| CVE-2018-14839                                          |      ❌      | RCE need call back .                                    |   2019-05-14   |
| CVE-2019-3568                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-05-14   |
| CVE-2019-11510                                          |      ✅      | Official Nuclei template.                               |   2019-05-08   |
| CVE-2017-18368                                          |      ❌      | Metasploit module without a check/check_code.           |   2019-05-02   |
| CVE-2019-3929                                           |      ✅      | Official Nuclei template.                               |   2019-04-30   |
| CVE-2019-2725                                           |      ✅      | Official Nuclei template.                               |   2019-04-26   |
| CVE-2019-11539                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-25   |
| CVE-2019-2616                                           |      ✅      | Official Nuclei template.                               |   2019-04-23   |
| CVE-2019-3398                                           |      ✅      | Official Nuclei template.                               |   2019-04-18   |
| CVE-2019-0803                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-09   |
| CVE-2019-0752                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-09   |
| CVE-2019-0841                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-09   |
| CVE-2019-0859                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-09   |
| CVE-2019-0797                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-08   |
| CVE-2019-0808                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-08   |
| CVE-2019-0703                                           |      ❌      | Missing public exploit.                                 |   2019-04-08   |
| CVE-2019-0211                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-08   |
| CVE-2018-4344                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-04-03   |
| CVE-2019-9193                                           |      ✅      | Covered by tsunami scanner.                             |   2019-04-01   |
| CVE-2019-10068                                          |      ✅      | Official Nuclei template.                               |   2019-03-26   |
| CVE-2019-7609                                           |      ✅      | Official Nuclei template.                               |   2019-03-25   |
| CVE-2019-3396                                           |      ✅      | Official Nuclei template.                               |   2019-03-25   |
| CVE-2019-9978                                           |      ✅      | Official Nuclei template.                               |   2019-03-24   |
| CVE-2018-0153                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-21   |
| CVE-2019-7238                                           |      ✅      | Official Nuclei template.                               |   2019-03-21   |
| CVE-2019-1003029                                        |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-08   |
| CVE-2019-1003030                                        |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-08   |
| CVE-2018-18809                                          |      ✅      | Official Nuclei template.                               |   2019-03-07   |
| CVE-2019-6223                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-05   |
| CVE-2019-0604                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-05   |
| CVE-2019-0676                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-03-05   |
| CVE-2019-9082                                           |      ✅      | Metasploit module.                                      |   2019-02-24   |
| CVE-2019-6340                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2019-02-21   |
| CVE-2019-8394                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-02-16   |
| CVE-2018-20250                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-02-05   |
| CVE-2018-20753                                          |      ❌      | Missing public exploit.                                 |   2019-02-05   |
| CVE-2017-18362                                          |      ❌      | Missing public exploit.                                 |   2019-02-05   |
| CVE-2019-1652                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-01-24   |
| CVE-2019-1653                                           |      ✅      | Official Nuclei template.                               |   2019-01-24   |
| CVE-2018-13374                                          |      ❌      | Required credentials.                                   |   2019-01-22   |
| CVE-2018-15982                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-01-18   |
| CVE-2019-0543                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-01-08   |
| CVE-2019-0541                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2019-01-08   |
| CVE-2018-19323                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-21   |
| CVE-2018-19320                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-21   |
| CVE-2018-19321                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-21   |
| CVE-2018-19322                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-21   |
| CVE-2018-8653                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-20   |
| CVE-2018-8611                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-11   |
| CVE-2018-17480                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-12-11   |
| CVE-2018-20062                                          |      ✅      | Metasploit module.                                      |   2018-12-11   |
| CVE-2018-1000861                                        |      ✅      | Official Nuclei template.                               |   2018-12-10   |
| CVE-2018-19410                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid. |   2018-11-21   |
| CVE-2018-17463                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-11-14   |
| CVE-2018-6065                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-11-14   |
| CVE-2018-8589                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-11-13   |
| CVE-2018-8581                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-11-13   |
| CVE-2018-14667                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2018-11-06   |
| CVE-2018-14558                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2018-10-30   |
| CVE-2018-8453                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-10-10   |
| CVE-2018-15961                                          |      ✅      | Official Nuclei template.                               |   2018-09-25   |
| CVE-2018-8440                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-09-12   |
| CVE-2018-11776                                          |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2018-08-22   |
| CVE-2018-8405                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-08-15   |
| CVE-2018-8373                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-08-15   |
| CVE-2018-8414                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-08-15   |
| CVE-2018-8406                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-08-15   |
| CVE-2018-14847                                          |      ❌      | Metasploit module without a check/check_code.           |   2018-08-02   |
| CVE-2018-7602                                           |      ✅      | Official Nuclei template.                               |   2018-07-19   |
| CVE-2018-8298                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-07-10   |
| CVE-2018-4990                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-07-09   |
| CVE-2018-5002                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-07-09   |
| CVE-2016-9079                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-06-11   |
| CVE-2018-6961                                           |      ❌      | Call back needed .                                      |   2018-06-11   |
| CVE-2018-0296                                           |      ✅      | Official Nuclei template.                               |   2018-06-07   |
| CVE-2018-11138                                          |      ✅      | Metasploit module.                                      |   2018-05-31   |
| CVE-2018-4939                                           |      ❌      | Missing public exploit.                                 |   2018-05-19   |
| CVE-2018-8174                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-05-09   |
| CVE-2018-8120                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-05-09   |
| CVE-2018-10562                                          |      ✅      | Official Nuclei template.                               |   2018-05-03   |
| CVE-2018-10561                                          |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2018-05-03   |
| CVE-2018-2628                                           |      ✅      | Metasploit module.                                      |   2018-04-18   |
| CVE-2018-5430                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-04-17   |
| CVE-2018-1273                                           |      ✅      | Official Nuclei template.                               |   2018-04-11   |
| CVE-2018-7600                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2018-03-29   |
| CVE-2018-0155                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0171                                           |      ❌      | DOS attack.                                             |   2018-03-28   |
| CVE-2018-0151                                           |      ✅      | Covered by tsunami scanner.                             |   2018-03-28   |
| CVE-2018-0154                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0156                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0158                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0159                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0167                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0161                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0172                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0173                                           |      ❌      | Missing public exploit.                                 |   2018-03-28   |
| CVE-2018-0174                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0175                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0179                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-0180                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-28   |
| CVE-2018-6882                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-27   |
| CVE-2017-12319                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-27   |
| CVE-2018-7445                                           |      ❌      | Missing public exploit.                                 |   2018-03-19   |
| CVE-2018-0147                                           |      ❌      | Missing public exploit.                                 |   2018-03-08   |
| CVE-2018-6530                                           |      ✅      | Official Nuclei template.                               |   2018-03-06   |
| CVE-2018-2380                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-03-01   |
| CVE-2018-6789                                           |      ❌      | Memory corruption and needs a shell back                |   2018-02-08   |
| CVE-2018-0125                                           |      ❌      | Missing public exploit.                                 |   2018-02-08   |
| CVE-2018-4878                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-02-06   |
| CVE-2017-1000353                                        |      ✅      | Google Tsunami Detector.                                |   2018-01-29   |
| CVE-2018-0802                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-01-09   |
| CVE-2018-0798                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2018-01-09   |
| CVE-2017-1000486                                        |      ✅      | Official Nuclei template.                               |   2018-01-03   |
| CVE-2017-17562                                          |      ✅      | Official Nuclei template.                               |   2017-12-12   |
| CVE-2017-15944                                          |      ✅      | Official Nuclei template.                               |   2017-12-11   |
| CVE-2017-11882                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-11-14   |
| CVE-2017-16651                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-11-09   |
| CVE-2017-5070                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-10-27   |
| CVE-2017-11292                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-10-22   |
| CVE-2017-10271                                          |      ✅      | Official Nuclei template.                               |   2017-10-19   |
| CVE-2017-11774                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-10-13   |
| CVE-2017-11826                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-10-13   |
| CVE-2017-12149                                          |      ✅      | Official Nuclei template.                               |   2017-10-04   |
| CVE-2017-12617                                          |      ✅      | Official Nuclei template.                               |   2017-10-03   |
| CVE-2017-12231                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12232                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12240                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12238                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12237                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12235                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12234                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2017-12233                                          |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-28   |
| CVE-2015-1187                                           |      ✅      | Metasploit module.                                      |   2017-09-21   |
| CVE-2017-12615                                          |      ✅      | Official Nuclei template.                               |   2017-09-19   |
| CVE-2017-9805                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2017-09-15   |
| CVE-2017-8759                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-12   |
| CVE-2017-6627                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-09-07   |
| CVE-2017-11317                                          |      ❌      | Metasploit module without a check/check_code.           |   2017-08-23   |
| CVE-2017-11357                                          |      ⏳      |                                                         |   2017-08-23   |
| CVE-2017-6327                                           |      ❌      | Authentication Required .                               |   2017-08-11   |
| CVE-2015-2291                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-08-09   |
| CVE-2017-6663                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-08-07   |
| CVE-2017-6316                                           |      ❌      | Missing public exploit.                                 |   2017-07-20   |
| CVE-2017-9822                                           |      ✅      | Official Nuclei template.                               |   2017-07-20   |
| CVE-2017-6740                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6744                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6743                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6742                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6739                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6738                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6737                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-6736                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-17   |
| CVE-2017-8570                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-07-11   |
| CVE-2017-9791                                           |      ✅      | Official Nuclei template.                               |   2017-07-10   |
| CVE-2017-9248                                           |      ✅      | Custom Nuclei template by Ostorlab.                     |   2017-07-03   |
| CVE-2017-9841                                           |      ✅      | Official Nuclei template.                               |   2017-06-27   |
| CVE-2017-8464                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-06-14   |
| CVE-2017-8543                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-06-14   |
| CVE-2017-7494                                           |      ✅      | Metasploit module.                                      |   2017-05-30   |
| CVE-2017-8540                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-26   |
| CVE-2017-6862                                           |      ❌      | Missing public exploit.                                 |   2017-05-26   |
| CVE-2017-0263                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-12   |
| CVE-2017-0262                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-12   |
| CVE-2017-0261                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-12   |
| CVE-2017-0222                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-12   |
| CVE-2017-0213                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-05-12   |
| CVE-2017-5689                                           |      ✅      | Official Nuclei template.                               |   2017-05-02   |
| CVE-2017-8291                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-04-26   |
| CVE-2017-5030                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-04-24   |
| CVE-2016-1555                                           |      ✅      | Official Nuclei template.                               |   2017-04-21   |
| CVE-2017-7615                                           |      ✅      | Covered by tsunami scanner.                             |   2017-04-16   |
| CVE-2017-0199                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-04-12   |
| CVE-2017-0210                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-04-12   |
| CVE-2016-8735                                           |      ❌      | Ignored for now as vulnerable env setup takes time.     |   2017-04-06   |
| CVE-2017-6884                                           |      ❌      | Authentication Required .                               |   2017-04-06   |
| CVE-2017-7269                                           |      ✅      | Metasploit module.                                      |   2017-03-26   |
| CVE-2017-3881                                           |      ❌      | Metasploit module without a check/check_code.           |   2017-03-17   |
| CVE-2017-0059                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0148                                           |      ✅      | Metasploit module.                                      |   2017-03-16   |
| CVE-2017-0001                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0005                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0022                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0149                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0146                                           |      ❌      | Metasploit module without a check/check_code.           |   2017-03-16   |
| CVE-2017-0101                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-16   |
| CVE-2017-0143                                           |      ✅      | Metasploit module.                                      |   2017-03-16   |
| CVE-2017-0144                                           |      ✅      | Metasploit module.                                      |   2017-03-16   |
| CVE-2017-0147                                           |      ✅      | Metasploit module.                                      |   2017-03-16   |
| CVE-2017-0145                                           |      ✅      | Metasploit module.                                      |   2017-03-16   |
| CVE-2017-5638                                           |      ✅      | Official Nuclei template and Tsunami scanner were used. |   2017-03-10   |
| CVE-2017-6334                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-03-05   |
| CVE-2017-0037                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-02-26   |
| CVE-2017-6077                                           |      ❌      | Authentication Required .                               |   2017-02-22   |
| CVE-2016-10174                                          |      ❌      | Metasploit module without a check/check_code.           |   2017-01-29   |
| CVE-2016-5198                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2017-01-19   |
| CVE-2017-5521                                           |      ✅      | Official Nuclei template.                               |   2017-01-17   |
| CVE-2016-7262                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-12-20   |
| CVE-2016-7892                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-12-15   |
| CVE-2016-6277                                           |      ✅      | Official Nuclei template.                               |   2016-12-14   |
| CVE-2016-9563                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-22   |
| CVE-2016-8562                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-18   |
| CVE-2016-5195                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-10   |
| CVE-2016-7255                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-10   |
| CVE-2016-7200                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-10   |
| CVE-2016-7201                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-10   |
| CVE-2016-7256                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-10   |
| CVE-2016-7855                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-11-01   |
| CVE-2016-7193                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-10-13   |
| CVE-2016-3393                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-10-13   |
| CVE-2016-3298                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-10-13   |
| CVE-2016-6415                                           |      ❌      | Metasploit module without a check/check_code.           |   2016-09-18   |
| CVE-2016-3351                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-09-14   |
| CVE-2016-4657                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-25   |
| CVE-2016-4656                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-25   |
| CVE-2016-4655                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-25   |
| CVE-2016-6366                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-18   |
| CVE-2016-6367                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-18   |
| CVE-2016-3309                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-08-09   |
| CVE-2016-3643                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-06-17   |
| CVE-2016-4171                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-06-16   |
| CVE-2016-3235                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-06-15   |
| CVE-2016-4523                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-06-09   |
| CVE-2016-4437                                           |      ✅      | Official Nuclei template.                               |   2016-06-07   |
| CVE-2016-3088                                           |      ✅      | Official Nuclei template.                               |   2016-06-01   |
| CVE-2010-5326                                           |      ❌      | Missing public exploit.                                 |   2016-05-13   |
| CVE-2016-0185                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-05-10   |
| CVE-2016-0189                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-05-10   |
| CVE-2016-4117                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-05-10   |
| CVE-2016-3715                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-05-05   |
| CVE-2016-3718                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-05-05   |
| CVE-2016-3427                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-21   |
| CVE-2016-0167                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-12   |
| CVE-2016-0165                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-12   |
| CVE-2016-0162                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-12   |
| CVE-2016-0151                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-12   |
| CVE-2016-1019                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-04-07   |
| CVE-2016-3976                                           |      ❌      | Missing public exploit.                                 |   2016-04-07   |
| CVE-2016-1646                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-03-29   |
| CVE-2016-1010                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-03-12   |
| CVE-2016-0099                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-03-09   |
| CVE-2016-2386                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2016-02-16   |
| CVE-2016-2388                                           |      ❌      | Information disclosure .                                |   2016-02-16   |
| CVE-2016-0752                                           |      ✅      | Metasploit module.                                      |   2016-02-15   |
| CVE-2016-0040                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-02-10   |
| CVE-2016-0984                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-02-10   |
| CVE-2016-0034                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2016-01-13   |
| CVE-2015-7450                                           |      ✅      | Official Nuclei template.                               |   2016-01-02   |
| CVE-2015-8651                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-12-28   |
| CVE-2015-8562                                           |      ✅      | Covered by tsunami scanner.                             |   2015-12-16   |
| CVE-2015-6175                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-12-09   |
| CVE-2015-5317                                           |      ❌      | Information disclosure: with False poc.                 |   2015-11-25   |
| CVE-2015-4852                                           |      ❌      | Metasploit module without a check/check_code.           |   2015-11-18   |
| CVE-2015-4902                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-10-21   |
| CVE-2015-7645                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-10-15   |
| CVE-2015-2546                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-09-08   |
| CVE-2015-2545                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-09-08   |
| CVE-2015-2502                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-08-19   |
| CVE-2015-1769                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-08-14   |
| CVE-2015-1642                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-08-14   |
| CVE-2015-4495                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-08-07   |
| CVE-2015-2426                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-20   |
| CVE-2015-2590                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-16   |
| CVE-2015-2424                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-2419                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-2387                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-2425                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-5123                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-5122                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-14   |
| CVE-2015-5119                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-07-08   |
| CVE-2015-3113                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-06-23   |
| CVE-2015-2360                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-06-09   |
| CVE-2015-1770                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-06-09   |
| CVE-2015-4068                                           |      ❌      | Not enough technical details available.                 |   2015-05-29   |
| CVE-2015-1671                                           |      ✅      | Official Nuclei template.                               |   2015-05-13   |
| CVE-2014-8361                                           |      ❌      | Metasploit module without a check/check_code.           |   2015-05-01   |
| CVE-2015-1701                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-04-21   |
| CVE-2015-3035                                           |      ✅      | Official Nuclei template.                               |   2015-04-21   |
| CVE-2015-1641                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-04-14   |
| CVE-2015-1635                                           |      ✅      | Custom nuclei template by Ostorlab.                     |   2015-04-14   |
| CVE-2015-3043                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-04-14   |
| CVE-2015-1130                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-04-10   |
| CVE-2015-0666                                           |      ❌      | Not enough technical details available.                 |   2015-04-03   |
| CVE-2015-2051                                           |      ❌      | Metasploit module without a check/check_code.           |   2015-02-23   |
| CVE-2015-1427                                           |      ✅      | Official Nuclei template.                               |   2015-02-17   |
| CVE-2015-0071                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-02-10   |
| CVE-2015-0313                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-02-02   |
| CVE-2015-0311                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-01-23   |
| CVE-2015-0310                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-01-23   |
| CVE-2015-0016                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2015-01-13   |
| CVE-2014-9163                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-12-10   |
| CVE-2014-8439                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-11-25   |
| CVE-2014-6324                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-11-18   |
| CVE-2014-6332                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-11-11   |
| CVE-2014-4077                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-11-11   |
| CVE-2014-6352                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-10-22   |
| CVE-2014-4113                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-10-15   |
| CVE-2014-4148                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-10-15   |
| CVE-2014-4123                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-10-15   |
| CVE-2014-4114                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-10-15   |
| CVE-2014-6287                                           |      ✅      | Official Nuclei template.                               |   2014-10-07   |
| CVE-2014-6271                                           |      ✅      | Official Nuclei template.                               |   2014-09-24   |
| CVE-2014-7169                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2014-09-24   |
| CVE-2014-4404                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-09-18   |
| CVE-2013-2597                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-08-31   |
| CVE-2014-2817                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-08-12   |
| CVE-2014-0546                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-08-12   |
| CVE-2014-3120                                           |      ✅      | Official Nuclei template.                               |   2014-07-28   |
| CVE-2013-3993                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-07-07   |
| CVE-2014-3153                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-06-07   |
| CVE-2014-1812                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-05-14   |
| CVE-2014-0130                                           |      ❌      | Missing public exploit.                                 |   2014-05-07   |
| CVE-2014-0196                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-05-07   |
| CVE-2014-1776                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-04-27   |
| CVE-2014-0780                                           |      ✅      | Custom Exploit by Ostorlab: included in Agent Asteroid  |   2014-04-25   |
| CVE-2014-0160                                           |      ✅      | Metasploit module.                                      |   2014-04-07   |
| CVE-2014-1761                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-03-25   |
| CVE-2013-7331                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-02-26   |
| CVE-2014-0322                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-02-14   |
| CVE-2014-0496                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2014-01-15   |
| CVE-2013-3900                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-12-10   |
| CVE-2013-5065                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-11-27   |
| CVE-2013-6282                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-11-20   |
| CVE-2013-5223                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-11-18   |
| CVE-2013-3906                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-11-06   |
| CVE-2013-3897                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-10-09   |
| CVE-2013-3896                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-10-09   |
| CVE-2013-4810                                           |      ❌      | Memory corruption .                                     |   2013-09-16   |
| CVE-2013-3346                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-08-30   |
| CVE-2013-2251                                           |      ✅      | Official Nuclei template.                               |   2013-07-19   |
| CVE-2013-3163                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-07-09   |
| CVE-2013-1690                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-06-25   |
| CVE-2013-2465                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-06-18   |
| CVE-2013-1331                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-06-11   |
| CVE-2013-3660                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-05-24   |
| CVE-2013-2729                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-05-16   |
| CVE-2013-1675                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-05-16   |
| CVE-2013-2094                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-05-14   |
| CVE-2013-1347                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-05-05   |
| CVE-2013-2423                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-04-17   |
| CVE-2013-2596                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-04-12   |
| CVE-2013-0074                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-03-12   |
| CVE-2013-2551                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-03-11   |
| CVE-2013-0640                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-02-13   |
| CVE-2013-0641                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-02-13   |
| CVE-2013-0431                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-01-31   |
| CVE-2013-0632                                           |      ✅      | Metasploit module.                                      |   2013-01-16   |
| CVE-2013-0422                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2013-01-10   |
| CVE-2013-0629                                           |      ✅      | Metasploit module.                                      |   2013-01-08   |
| CVE-2013-0631                                           |      ✅      | Metasploit module.                                      |   2013-01-08   |
| CVE-2013-0625                                           |      ✅      | Metasploit module.                                      |   2013-01-08   |
| CVE-2012-2539                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-12-11   |
| CVE-2012-5076                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-10-16   |
| CVE-2012-3153                                           |      ✅      | Same Nuclei template as CVE-2012-3152.                  |   2012-10-16   |
| CVE-2012-3152                                           |      ✅      | Official Nuclei template.                               |   2012-10-16   |
| CVE-2012-0518                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-10-16   |
| CVE-2012-5054                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-09-24   |
| CVE-2012-4969                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-09-18   |
| CVE-2012-4681                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-08-27   |
| CVE-2012-1535                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-08-15   |
| CVE-2012-1856                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-08-14   |
| CVE-2012-1723                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-06-16   |
| CVE-2012-1889                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-06-13   |
| CVE-2012-2034                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-06-08   |
| CVE-2012-0507                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-06-07   |
| CVE-2012-1823                                           |      ✅      | Metasploit module and Tsunami scanner were used.        |   2012-05-11   |
| CVE-2012-1710                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-05-03   |
| CVE-2012-0151                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-04-10   |
| CVE-2012-0158                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-04-10   |
| CVE-2012-0754                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-02-16   |
| CVE-2012-0767                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2012-02-16   |
| CVE-2012-0391                                           |      ❌      | Metasploit module without a check/check_code.           |   2012-01-08   |
| CVE-2011-4723                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-12-20   |
| CVE-2011-2462                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-12-07   |
| CVE-2011-3544                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-10-19   |
| CVE-2011-2005                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-10-11   |
| CVE-2011-1889                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-06-16   |
| CVE-2011-1823                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-06-09   |
| CVE-2011-0611                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-04-13   |
| CVE-2011-0609                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2011-03-15   |
| CVE-2010-4344                                           |      ❌      | Metasploit module without a check/check_code.           |   2010-12-14   |
| CVE-2010-4345                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-12-14   |
| CVE-2010-3904                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-12-06   |
| CVE-2010-4398                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-12-06   |
| CVE-2010-3333                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-11-09   |
| CVE-2010-2572                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-11-09   |
| CVE-2010-2883                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-09-09   |
| CVE-2010-3035                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-08-30   |
| CVE-2010-2861                                           |      ✅      | Official Nuclei template.                               |   2010-08-11   |
| CVE-2010-1871                                           |      ✅      | Metasploit module.                                      |   2010-08-05   |
| CVE-2010-2568                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-07-22   |
| CVE-2010-1297                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-06-08   |
| CVE-2010-1428                                           |      ❌      | Metasploit module without a check/check_code.           |   2010-04-28   |
| CVE-2010-0738                                           |      ❌      | Metasploit module without a check/check_code.           |   2010-04-28   |
| CVE-2010-0840                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-04-01   |
| CVE-2010-0188                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-02-22   |
| CVE-2009-3960                                           |      ❌      | Metasploit module without a check/check_code.           |   2010-02-15   |
| CVE-2010-0232                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-01-21   |
| CVE-2009-3953                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2010-01-13   |
| CVE-2009-4324                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-12-14   |
| CVE-2009-3129                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-11-11   |
| CVE-2009-2055                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-08-19   |
| CVE-2009-1862                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-07-23   |
| CVE-2009-1123                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-06-10   |
| CVE-2009-0563                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-06-10   |
| CVE-2009-0557                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-06-10   |
| CVE-2009-1151                                           |      ✅      | Official Nuclei template.                               |   2009-03-26   |
| CVE-2009-0927                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2009-03-19   |
| CVE-2008-2992                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2008-11-04   |
| CVE-2008-3431                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2008-08-05   |
| CVE-2007-5659                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2008-02-12   |
| CVE-2008-0655                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2008-02-07   |
| CVE-2007-3010                                           |      ❌      | Metasploit module without a check/check_code.           |   2007-09-18   |
| CVE-2006-2492                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2006-05-19   |
| CVE-2006-1547                                           |      ❌      | testing leads to DoS.                                   |   2006-03-30   |
| CVE-2005-2773                                           |      ❌      | Metasploit module without a check/check_code.           |   2005-09-02   |
| CVE-2004-1464                                           |      ❌      | Missing public exploit.                                 |   2004-12-31   |
| CVE-2004-0210                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2004-08-06   |
| CVE-2002-0367                                           |      ❌      | Not remotely exploitable/User interaction needed.       |   2002-06-25   |
| Selenium exposure.                                      |      ✅      | Official Nuclei template.                               |       -        |
| Generic Path Traversal vulnerabilities.                 |      ✅      | Tsunami Detector.                                       |       -        |
| Apache NiFi API Exposed UI.                             |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Argo Workflows instances.                       |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Docker API.                                     |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Elasticsearch API.                              |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Hadoop Yarn ResourceManager API.                |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Jenkins UI.                                     |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Jupyter Notebook.                               |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Kubernetes API.                                 |      ✅      | Tsunami Detector.                                       |       -        |
| Information leak via Kubernetes read-only-port feature. |      ✅      | Tsunami Detector.                                       |       -        |
| PHPUnit Exposed Vulnerable eval-stdin.php.              |      ✅      | Tsunami Detector.                                       |       -        |
| Exposed Spring Boot Actuator Endpoint.                  |      ✅      | Tsunami Detector.                                       |       -        |
| WordPress Exposed Installation Page.                    |      ✅      | Tsunami Detector.                                       |       -        |
| Consul RCE.                                             |      ✅      | Tsunami Detector.                                       |       -        |
| Unauthenticated Redis allowing RCE.                     |      ✅      | Tsunami Detector.                                       |       -        |
| Cisco SMI Protocol.                                     |      ✅      | Tsunami Detector.                                       |       -        |
| Apache Solr RemoteStreaming Arbitrary File Reading.     |      ✅      | Tsunami Detector.                                       |       -        |
| Jira Authentication Bypass Vulnerability.               |      ✅      | Tsunami Detector.                                       |       -        |
| Kubernetes Open Access Remote Code Execution.           |      ✅      | Tsunami Detector.                                       |       -        |
| Selenium Grid - RCE via Chrome webdriver.               |      ✅      | Tsunami Detector.                                       |       -        |
| GoCD Pre-Auth Arbitrary File Reading vulnerability.     |      ✅      | Tsunami Detector.                                       |       -        |
