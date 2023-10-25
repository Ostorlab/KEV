# Known Exploited Vulnerabilities Detector

## Introduction

Welcome to the Known Exploited Vulnerabilities Detector repository! This project is dedicated to enhancing the security of companies and organizations by identifying  known exploited vulnerabilities. Our goal is to provide a comprehensive solution that helps protect your digital assets and maintain a strong security posture.

## Project Purpose

In an ever-evolving digital landscape, businesses and organizations are under constant threat from cyberattacks. Hackers often target known vulnerabilities in software, networks, and systems to gain unauthorized access or compromise data. The Known Exploited Vulnerabilities Detector project aims to:

- Identify and catalog a wide range of known vulnerabilities that have been exploited in the past.
- Gather and develop tools to detect these vulnerabilities in your environment.

## What's Inside

This repository is structured to facilitate effective vulnerability detection and mitigation:

1. **Vulnerability Database**: A comprehensive database containing information about known vulnerabilities, their CVE IDs (Common Vulnerabilities and Exposures), and references to relevant security advisories.

2. **Detection Tools**: We offer a set of open-source detection tools and scripts that can be used to identify these known vulnerabilities within your organization's infrastructure.

3. **Resources**: A curated list of external resources, including links to essential websites, research papers, and books, to help you stay updated and informed about the ever-changing threat landscape.

4. **Community Contributions**: We encourage contributions from the security community. If you have insights, tools, or resources to share, please contribute and help strengthen the collective security knowledge base.

## Current Coverage

For the moment, we are currently focused on the CISA KEV Database. However, we have plans to expand our coverage to include more databases in the future. You can find details about different CVEs in the following sheet:
 
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
ostorlab scan run --install -g agentGroup.yaml ip 8.8.8.8
```

And you can scan more than one IP address by specifying them, separated by spaces:
```shell
ostorlab scan run --install -g agentGroup.yaml ip 8.8.8.8 1.1.1.1
```
This command will download and install the agents specified in the YAML file and target the provided IP addresses, such as 8.8.8.8 and 1.1.1.1.

### Scanning a Domain:

To scan a domain , simply run the following command:

```shell
ostorlab scan run --install -g agentGroup.yaml domain-name example.com
```
This command will download and install the required agents specified in the YAML file and perform the scan on the domain "example.com."

### Scanning a Link:

To scan a link, simply run the following command:

```shell
ostorlab scan run --install -g agentGroup.yaml link --url https://example.com --method GET
```
This command will download and install the required agents specified in the YAML file and perform the scan on the link "https[.]example[.]com" using the specified method.
