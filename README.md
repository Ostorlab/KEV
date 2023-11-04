# Known Exploited Vulnerabilities Detector

## Introduction

This project is dedicated to the detection of known exploited vulnerabilities. Our goal is to provide a single command to detect all of these vulnerabilities.

## Current Coverage

For the moment, we are currently focused on the CISA KEV Database and Google Tsunami.

🔗 [CVE Details Spreadsheet](https://docs.google.com/spreadsheets/d/1z-d5oWDjvFP66otAtndPW-GRfS05-ElA0p5AwfcGjrQ/edit?usp=sharing)

## Requirements

Docker is required to run scans locally. To install docker, please follow these
[instructions](https://docs.docker.com/get-docker/).

## Installing

Ostorlab ships as a Python package on pypi. To install it, simply run the following command if you have `pip` already
installed.

```shell
pip install -U ostorlab
```

## Getting Started

To perform your first scan, you have several options depending on your target. Here's how you can get started:

### Scanning an IP Address

To scan an IP address, simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml ip 8.8.8.8
```

And you can scan more than one IP address by specifying them, separated by spaces:

```shell
ostorlab scan run --install -g agent_group.yaml ip 8.8.8.8 1.1.1.1 4.4.4.0/24
```

### Scanning a Domain:

To scan a domain , simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml domain-name example.com
```

This command will download and install the required agents specified in the YAML file and perform the scan on the
domain "example.com."

### Scanning a Link:

To scan a link, simply run the following command:

```shell
ostorlab scan run --install -g agent_group.yaml link --url https://example.com --method GET
```

This command will download and install the required agents specified in the YAML file and perform the scan on the link "
https[.]example[.]com" using the specified method.

### Targeting all subdomains

The vulnerability detectin can be paired with other tools like `subfinder` or `dnsx` to target all subdomains.

Add the value:
```yaml
agent:
  - key: agent/ostorlab/subfinder
  - key: agent/ostorlab/dnsx

```

And the run it the domain you would like to taget:

```shell
ostorlab scan run --install -g agent_group.yaml domain-name example.com
```
