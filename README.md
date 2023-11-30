# Known Exploited Vulnerabilities Detector

## Introduction

This project is dedicated to the detection of known exploited vulnerabilities. Our goal is to provide a single command to detect all of these vulnerabilities.

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


## Current Coverage

For the moment, we are currently focused on the CISA KEV Database and Google Tsunami.

| CVE ID           | Implemented | Note                                              |
|------------------|-------------|---------------------------------------------------|
| CVE-2002-0367    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2004-0210    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2004-1464    | ❌           | Missing public exploit.                           |
| CVE-2005-2773    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2006-2492    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2007-3010    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2007-5659    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2008-0655    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2008-2992    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2008-3431    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-0557    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-0563    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-0927    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-1123    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-1151    | ✅           | Nuclei Template was used.                         |
| CVE-2009-1862    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-2055    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-3129    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-3953    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2009-3960    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2009-4324    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-0188    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-0232    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-0738    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2010-0840    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-1297    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-1428    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2010-1871    | ✅           | Metasploit module was used.                       |
| CVE-2010-2568    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-2572    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-2861    | ✅           | Nuclei Template was used.                         |
| CVE-2010-2883    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-3035    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-3333    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-3904    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-4344    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2010-4345    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-4398    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2010-5326    | ❌           | Missing public exploit.                           |
| CVE-2010-5330    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-0609    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-0611    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-1823    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-1889    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-2005    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-2462    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-3544    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2011-4723    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0151    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0158    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0391    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2012-0507    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0518    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0754    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-0767    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-1535    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-1710    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-1723    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-1823    | ✅           | Metasploit module was used.                       |
| CVE-2012-1856    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-1889    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-2034    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-2539    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-3152    | ✅           | Metasploit module was used.                       |
| CVE-2012-4681    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-4969    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-5054    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2012-5076    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-0074    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-0422    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-0431    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-0625    | ✅           | Metasploit module was used.                       |
| CVE-2013-0629    | ✅           | Metasploit module was used.                       |
| CVE-2013-0631    | ✅           | Metasploit module was used.                       |
| CVE-2013-0632    | ✅           | Metasploit module was used.                       |
| CVE-2013-0640    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-0641    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-1331    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-1347    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-1675    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-1690    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2094    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2251    | ✅           | Nuclei Template was used.                         |
| CVE-2013-2423    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2465    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2551    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2596    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2597    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-2729    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3163    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3346    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3660    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3896    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3897    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3900    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3906    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-3993    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-4810    | ❌           | Memory corruption .                               |
| CVE-2013-5065    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-5223    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-6282    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2013-7331    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-0130    | ❌           | Missing public exploit.                           |
| CVE-2014-0160    | ✅           | Metasploit module was used.                       |
| CVE-2014-0196    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-0322    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-0496    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-0546    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-0780    | ⏳           |                                                   |
| CVE-2014-1761    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-1776    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-1812    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-2817    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-3120    | ✅           | Nuclei Template was used.                         |
| CVE-2014-3153    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4077    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4113    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4114    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4123    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4148    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-4404    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-6271    | ✅           | Metasploit module was used.                       |
| CVE-2014-6287    | ✅           | Nuclei Template was used.                         |
| CVE-2014-6324    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-6332    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-6352    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-7169    | ✅           | Added to Asteroid.                                |
| CVE-2014-8361    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2014-8439    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2014-9163    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-0016    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-0071    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-0310    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-0311    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-0313    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1130    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1187    | ✅           | Metasploit module was used.                       |
| CVE-2015-1427    | ✅           | Nuclei Template was used.                         |
| CVE-2015-1635    | ✅           | Metasploit module was used.                       |
| CVE-2015-1641    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1642    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1671    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1701    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1769    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-1770    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2051    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2015-2291    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2360    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2387    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2419    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2424    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2425    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2426    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2502    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2545    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2546    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-2590    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-3035    | ✅           | Nuclei Template was used.                         |
| CVE-2015-3043    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-3113    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-4495    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-4852    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2015-4902    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-5119    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-5122    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-5123    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-5317    | ❌           | Information discolsure: with False poc.           |
| CVE-2015-6175    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-7450    | ✅           | Nuclei Template was used.                         |
| CVE-2015-7645    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2015-8651    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0034    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0040    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0099    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0151    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0162    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0165    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0167    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0185    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0189    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-0752    | ✅           | Metasploit module was used.                       |
| CVE-2016-0984    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-1010    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-10174   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2016-1019    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-11021   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-1555    | ✅           | Nuclei Template was used.                         |
| CVE-2016-1646    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-2386    | ⏳           |                                                   |
| CVE-2016-2388    | ❌           | Information disclosure .                          |
| CVE-2016-3088    | ✅           | Nuclei Template was used.                         |
| CVE-2016-3235    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3298    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3309    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3351    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3393    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3427    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3643    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3715    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3718    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-3976    | ⏳           |                                                   |
| CVE-2016-4117    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-4171    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-4437    | ✅           | Nuclei Template was used.                         |
| CVE-2016-4523    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-4655    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-4656    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-4657    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-5195    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-5198    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-6277    | ✅           | Nuclei Template was used.                         |
| CVE-2016-6366    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-6367    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-6415    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2016-7193    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7200    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7201    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7255    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7256    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7262    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7855    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-7892    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-8562    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-9079    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2016-9563    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0001    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0005    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0022    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0037    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0059    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0101    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0143    | ✅           | Metasploit module was used.                       |
| CVE-2017-0144    | ✅           | Metasploit module was used.                       |
| CVE-2017-0145    | ✅           | Metasploit module was used.                       |
| CVE-2017-0146    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2017-0147    | ✅           | Metasploit module was used.                       |
| CVE-2017-0148    | ✅           | Metasploit module was used.                       |
| CVE-2017-0149    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0199    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0210    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0213    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0222    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0261    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0262    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-0263    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-1000486 | ✅           | Nuclei Template was used.                         |
| CVE-2017-10271   | ✅           | Nuclei Template was used.                         |
| CVE-2017-11292   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-11317   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2017-11357   | ⏳           |                                                   |
| CVE-2017-11774   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-11826   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-11882   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12149   | ✅           | Nuclei Template was used.                         |
| CVE-2017-12231   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12232   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12233   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12234   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12235   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12237   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12238   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12240   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12319   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-12615   | ✅           | Nuclei Template was used.                         |
| CVE-2017-12617   | ✅           | Nuclei Template was used.                         |
| CVE-2017-15944   | ✅           | Nuclei Template was used.                         |
| CVE-2017-16651   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-17562   | ✅           | Nuclei Template was used.                         |
| CVE-2017-18362   | ❌           | Missing public exploit.                           |
| CVE-2017-18368   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2017-3881    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2017-5030    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-5070    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-5521    | ✅           | Nuclei Template was used.                         |
| CVE-2017-5638    | ✅           | Nuclei Template was used.                         |
| CVE-2017-5689    | ✅           | Nuclei Template was used.                         |
| CVE-2017-6077    | ❌           | Authentication Required .                         |
| CVE-2017-6316    | ❌           | Missing public exploit.                           |
| CVE-2017-6327    | ❌           | Authentication Required .                         |
| CVE-2017-6334    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6627    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6663    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6736    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6737    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6738    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6739    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6740    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6742    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6743    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6744    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-6862    | ❌           | Missing public exploit.                           |
| CVE-2017-6884    | ❌           | Authentication Required .                         |
| CVE-2017-7269    | ✅           | Metasploit module was used.                       |
| CVE-2017-7494    | ✅           | Metasploit module was used.                       |
| CVE-2017-8291    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-8464    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-8540    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-8543    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-8570    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-8759    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2017-9248    | ⏳           |                                                   |
| CVE-2017-9791    | ✅           | Nuclei Template was used.                         |
| CVE-2017-9805    | ✅           | Nuclei Template was used.                         |
| CVE-2017-9822    | ✅           | Nuclei Template was used.                         |
| CVE-2017-9841    | ✅           | Nuclei Template was used.                         |
| CVE-2018-0125    | ❌           | Missing public exploit.                           |
| CVE-2018-0147    | ❌           | Missing public exploit.                           |
| CVE-2018-0153    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0154    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0155    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0156    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0158    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0159    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0161    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0167    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0171    | ❌           | DOS attack.                                       |
| CVE-2018-0172    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0173    | ❌           | Missing public exploit.                           |
| CVE-2018-0174    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0175    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0179    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0180    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0296    | ✅           | Nuclei Template was used.                         |
| CVE-2018-0798    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-0802    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-1000861 | ✅           | Nuclei Template was used.                         |
| CVE-2018-10561   | ✅           | Added to Asteroid.                                |
| CVE-2018-10562   | ✅           | Nuclei Template was used.                         |
| CVE-2018-11138   | ✅           | Metasploit module was used.                       |
| CVE-2018-11776   | ✅           | Nuclei Template was used.                         |
| CVE-2018-1273    | ✅           | Nuclei Template was used.                         |
| CVE-2018-13374   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-13379   | ✅           | Nuclei Template was used.                         |
| CVE-2018-13382   | ✅           | Added to Asteroid.                                |
| CVE-2018-13383   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-14558   | ✅           | Added to Asteroid.                                |
| CVE-2018-14667   | ⏳           |                                                   |
| CVE-2018-14839   | ❌           | RCE need call back .                              |
| CVE-2018-14847   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2018-15811   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2018-15961   | ✅           | Nuclei Template was used.                         |
| CVE-2018-15982   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-17463   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-17480   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-18325   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2018-18809   | ✅           | Nuclei Template was used.                         |
| CVE-2018-19320   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-19321   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-19322   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-19323   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-19943   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-19949   | ❌           | Missing public exploit.                           |
| CVE-2018-19953   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-20062   | ✅           | Metasploit module was used.                       |
| CVE-2018-20250   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-20753   | ❌           | Missing public exploit.                           |
| CVE-2018-2380    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-2628    | ✅           | Metasploit module was used.                       |
| CVE-2018-4344    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-4878    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-4939    | ⏳           |                                                   |
| CVE-2018-4990    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-5002    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-5430    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-6065    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-6530    | ✅           | Nuclei Template was used.                         |
| CVE-2018-6789    | ❌           | Memory corruption and needs a shell back          |
| CVE-2018-6882    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-6961    | ❌           | Call back needed .                                |
| CVE-2018-7445    | ❌           | Missing public exploit.                           |
| CVE-2018-7600    | ✅           | Nuclei Template was used.                         |
| CVE-2018-7602    | ✅           | Nuclei Template was used.                         |
| CVE-2018-7841    | ✅           | Added to Asteroid.                                |
| CVE-2018-8120    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8174    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8298    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8373    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8405    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8406    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8414    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8440    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8453    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8581    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8589    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8611    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2018-8653    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0193    | ✅           | Nuclei Template was used.                         |
| CVE-2019-0211    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0541    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0543    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0604    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0676    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0703    | ❌           | Missing public exploit.                           |
| CVE-2019-0708    | ✅           | Metasploit module was used.                       |
| CVE-2019-0752    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0797    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0803    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0808    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0841    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0859    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0863    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0880    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-0903    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1003029 | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1003030 | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-10068   | ✅           | Nuclei Template was used.                         |
| CVE-2019-10149   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1064    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1069    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-10758   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-11043   | ✅           | Metasploit module was used.                       |
| CVE-2019-1129    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1130    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1132    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-11510   | ✅           | Nuclei Template was used.                         |
| CVE-2019-11539   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-11580   | ✅           | Nuclei Template was used.                         |
| CVE-2019-11581   | ✅           | Nuclei Template was used.                         |
| CVE-2019-11634   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-11707   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-11708   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1214    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1215    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1253    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1297    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-12989   | ✅           | Added to Asteroid.                                |
| CVE-2019-12991   | ✅           | Added to Asteroid.                                |
| CVE-2019-1315    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1322    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-13272   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-13608   | ❌           | Missing public exploit.                           |
| CVE-2019-1367    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-13720   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1385    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1388    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1405    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1429    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1458    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-15107   | ✅           | Nuclei Template was used.                         |
| CVE-2019-15271   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-15752   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1579    | ✅           | Nuclei Template was used.                         |
| CVE-2019-15949   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-16057   | ✅           | Nuclei Template was used.                         |
| CVE-2019-16256   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1652    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-1653    | ✅           | Nuclei Template was used.                         |
| CVE-2019-16759   | ✅           | Nuclei Template was used.                         |
| CVE-2019-16920   | ✅           | Nuclei Template was used.                         |
| CVE-2019-16928   | ❌           | Missing public exploit.                           |
| CVE-2019-17026   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-17558   | ✅           | Nuclei Template was used.                         |
| CVE-2019-17621   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2019-18187   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-18426   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-18935   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2019-18988   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-19356   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-19781   | ✅           | Nuclei Template was used.                         |
| CVE-2019-20085   | ✅           | Nuclei Template was used.                         |
| CVE-2019-20500   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-2215    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-2616    | ✅           | Nuclei Template was used.                         |
| CVE-2019-2725    | ✅           | Nuclei Template was used.                         |
| CVE-2019-3010    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-3396    | ✅           | Nuclei Template was used.                         |
| CVE-2019-3398    | ✅           | Nuclei Template was used.                         |
| CVE-2019-3568    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-3929    | ✅           | Nuclei Template was used.                         |
| CVE-2019-4716    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2019-5544    | ❌           | Missing public exploit.                           |
| CVE-2019-5591    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-5786    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-5825    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-6223    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-6340    | ✅           | Nuclei Template was used.                         |
| CVE-2019-7192    | ✅           | Nuclei Template was used.                         |
| CVE-2019-7193    | ✅           | Added to Asteroid.                                |
| CVE-2019-7194    | ✅           | Metasploit module was used.                       |
| CVE-2019-7195    | ✅           | Metasploit module was used.                       |
| CVE-2019-7238    | ✅           | Nuclei Template was used.                         |
| CVE-2019-7286    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-7287    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-7481    | ✅           | Nuclei Template was used.                         |
| CVE-2019-7483    | ❌           | Missing public exploit.                           |
| CVE-2019-7609    | ✅           | Nuclei Template was used.                         |
| CVE-2019-8394    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-8506    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-8526    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-8605    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-8720    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2019-9082    | ✅           | Metasploit module was used.                       |
| CVE-2019-9670    | ✅           | Nuclei Template was used.                         |
| CVE-2019-9978    | ✅           | Nuclei Template was used.                         |
| CVE-2020-0041    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0069    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0601    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0638    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0646    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0674    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0683    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0688    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0787    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0796    | ✅           | Metasploit module was used.                       |
| CVE-2020-0878    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0938    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0968    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-0986    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-10148   | ✅           | Nuclei Template was used.                         |
| CVE-2020-10181   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-10189   | ✅           | Metasploit module was used.                       |
| CVE-2020-10199   | ✅           | Nuclei Template was used.                         |
| CVE-2020-1020    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-10221   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1027    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1040    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1054    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-10987   | ❌           | Authentication Required .                         |
| CVE-2020-11261   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1147    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-11651   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2020-11652   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2020-11738   | ✅           | Nuclei Template was used.                         |
| CVE-2020-11899   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-11978   | ✅           | Nuclei Template was used.                         |
| CVE-2020-12271   | ❌           | Missing public exploit.                           |
| CVE-2020-12641   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-12812   | ❌           | Missing public exploit.                           |
| CVE-2020-1350    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-13671   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1380    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-13927   | ✅           | Nuclei Template was used.                         |
| CVE-2020-1464    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1472    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-14750   | ✅           | Nuclei Template was used.                         |
| CVE-2020-14864   | ✅           | Nuclei Template was used.                         |
| CVE-2020-14871   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-14882   | ✅           | Nuclei Template was used.                         |
| CVE-2020-14883   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-15505   | ✅           | Nuclei Template was used.                         |
| CVE-2020-15999   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-16009   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-16010   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-16013   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-16017   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-1631    | ❌           | Missing public exploit.                           |
| CVE-2020-16846   | ✅           | Nuclei Template was used.                         |
| CVE-2020-17087   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-17144   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-17463   | ✅           | Nuclei Template was used.                         |
| CVE-2020-17496   | ✅           | Nuclei Template was used.                         |
| CVE-2020-17530   | ✅           | Nuclei Template was used.                         |
| CVE-2020-1938    | ✅           | Metasploit module was used.                       |
| CVE-2020-1956    | ✅           | Nuclei Template was used.                         |
| CVE-2020-2021    | ❌           | Missing public exploit.                           |
| CVE-2020-24557   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-2506    | ❌           | Missing public exploit.                           |
| CVE-2020-2509    | ❌           | Requires a MITM.                                  |
| CVE-2020-25213   | ✅           | Nuclei Template was used.                         |
| CVE-2020-25223   | ✅           | Nuclei Template was used.                         |
| CVE-2020-25506   | ✅           | Nuclei Template was used.                         |
| CVE-2020-2555    | ✅           | Metasploit module was used.                       |
| CVE-2020-26919   | ✅           | Nuclei Template was used.                         |
| CVE-2020-27930   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-27932   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-27950   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-28949   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-29583   | ✅           | Nuclei Template was used.                         |
| CVE-2020-3118    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3153    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3161    | ❌           | DOS attack.                                       |
| CVE-2020-3433    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3452    | ✅           | Nuclei Template was used.                         |
| CVE-2020-3566    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3569    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-35730   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3580    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-36193   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3837    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3950    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-3952    | ✅           | Metasploit module was used.                       |
| CVE-2020-3992    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-4006    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-4427    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2020-4428    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-4430    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2020-5135    | ❌           | Missing public exploit.                           |
| CVE-2020-5410    | ✅           | Nuclei Template was used.                         |
| CVE-2020-5722    | ✅           | Metasploit module was used.                       |
| CVE-2020-5735    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-5741    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-5847    | ✅           | Nuclei Template was used.                         |
| CVE-2020-5849    | ✅           | Metasploit module was used.                       |
| CVE-2020-5902    | ✅           | Nuclei Template was used.                         |
| CVE-2020-6207    | ✅           | Nuclei Template was used.                         |
| CVE-2020-6287    | ✅           | Nuclei Template was used.                         |
| CVE-2020-6418    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-6572    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-6819    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-6820    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-7247    | ❌           | Metasploit module without a check/check_code.     |
| CVE-2020-7961    | ✅           | Nuclei Template was used.                         |
| CVE-2020-8193    | ✅           | Nuclei Template was used.                         |
| CVE-2020-8195    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8196    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8218    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8243    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8260    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8467    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8468    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8515    | ✅           | Nuclei Template was used.                         |
| CVE-2020-8599    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8644    | ✅           | Nuclei Template was used.                         |
| CVE-2020-8655    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-8657    | ✅           | Metasploit module was used.                       |
| CVE-2020-8816    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9054    | ✅           | Nuclei Template was used.                         |
| CVE-2020-9377    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9818    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9819    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9859    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9907    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2020-9934    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-0920    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1048    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1497    | ✅           | Nuclei Template was used.                         |
| CVE-2021-1498    | ✅           | Nuclei Template was used.                         |
| CVE-2021-1647    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1675    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1732    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1782    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1789    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1870    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1871    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1879    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1905    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-1906    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-20016   | ❌           | Missing public exploit.                           |
| CVE-2021-20021   | ❌           | Missing public exploit.                           |
| CVE-2021-20022   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-20023   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-20028   | ❌           | Missing public exploit.                           |
| CVE-2021-20038   | ✅           | Nuclei Template was used.                         |
| CVE-2021-20090   | ✅           | Nuclei Template was used.                         |
| CVE-2021-21017   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21148   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21166   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21193   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21206   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21220   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21224   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21315   | ✅           | Nuclei Template was used.                         |
| CVE-2021-21551   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-21972   | ✅           | Nuclei Template was used.                         |
| CVE-2021-21973   | ✅           | Nuclei Template was used.                         |
| CVE-2021-21975   | ✅           | Nuclei Template was used.                         |
| CVE-2021-21985   | ✅           | Nuclei Template was used.                         |
| CVE-2021-22005   | ✅           | Nuclei Template was used.                         |
| CVE-2021-22017   | ❌           | Missing public exploit.                           |
| CVE-2021-22204   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22205   | ✅           | Nuclei Template was used.                         |
| CVE-2021-22502   | ✅           | Nuclei Template was used.                         |
| CVE-2021-22506   | ❌           | Missing public exploit.                           |
| CVE-2021-22600   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22893   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22894   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22899   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22900   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-22941   | ✅           | Added to Asteroid.                                |
| CVE-2021-22986   | ✅           | Nuclei Template was used.                         |
| CVE-2021-22991   | ❌           | Missing public exploit.                           |
| CVE-2021-23874   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25296   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25297   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25298   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25337   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25369   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25370   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25371   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25372   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25394   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25395   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25487   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-25489   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-26084   | ✅           | Nuclei Template was used.                         |
| CVE-2021-26085   | ✅           | Nuclei Template was used.                         |
| CVE-2021-26411   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-26855   | ✅           | Metasploit module was used.                       |
| CVE-2021-26857   | ✅           | Nuclei Template was used.                         |
| CVE-2021-26858   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27059   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27065   | ✅           | Metasploit module was used.                       |
| CVE-2021-27085   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27102   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27104   | ❌           | Missing public exploit.                           |
| CVE-2021-27105   | ❌           | Missing public exploit.                           |
| CVE-2021-27106   | ❌           | Missing public exploit.                           |
| CVE-2021-27107   | ❌           | Missing public exploit.                           |
| CVE-2021-27108   | ❌           | Missing public exploit.                           |
| CVE-2021-27109   | ❌           | Missing public exploit.                           |
| CVE-2021-27110   | ❌           | Missing public exploit.                           |
| CVE-2021-27111   | ❌           | Missing public exploit.                           |
| CVE-2021-27113   | ❌           | Missing public exploit.                           |
| CVE-2021-27114   | ❌           | Missing public exploit.                           |
| CVE-2021-27115   | ❌           | Missing public exploit.                           |
| CVE-2021-27116   | ❌           | Missing public exploit.                           |
| CVE-2021-27561   | ✅           | Nuclei Template was used.                         |
| CVE-2021-27562   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27860   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27876   | ✅           | Metasploit module was used.                       |
| CVE-2021-27877   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-27878   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-28310   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-28550   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-28663   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-28664   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-28799   | ❌           | Missing public exploit.                           |
| CVE-2021-29256   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30116   | ❌           | Missing public exploit.                           |
| CVE-2021-30533   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30551   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30554   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30563   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30632   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30633   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30657   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30661   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30663   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30665   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30666   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30713   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30761   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30762   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30807   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30858   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30860   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30869   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30883   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30900   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-30983   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31010   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31166   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2021-31199   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31201   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31207   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-3129    | ✅           | Nuclei Template was used.                         |
| CVE-2021-3156    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31755   | ✅           | Nuclei Template was used.                         |
| CVE-2021-31955   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31956   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-31979   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-32648   | ✅           | Added to Asteroid.                                |
| CVE-2021-33739   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-33742   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-33766   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-33771   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34448   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34473   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34484   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34486   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34523   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-34527   | ✅           | Metasploit module was used.                       |
| CVE-2021-3493    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-35211   | ❌           | Missing public exploit.                           |
| CVE-2021-35247   | ❌           | Missing public exploit.                           |
| CVE-2021-35394   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-35395   | ❌           | Missing public exploit.                           |
| CVE-2021-35464   | ✅           | Nuclei Template was used.                         |
| CVE-2021-35587   | ✅           | Nuclei Template was used.                         |
| CVE-2021-3560    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36260   | ✅           | Nuclei Template was used.                         |
| CVE-2021-36741   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36742   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36934   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36942   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36948   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-36955   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-37415   | ❌           | Missing public exploit.                           |
| CVE-2021-37973   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-37975   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-37976   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38000   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38003   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38163   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38406   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38645   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38646   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38647   | ✅           | Nuclei Template was used.                         |
| CVE-2021-38648   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-38649   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-39144   | ✅           | Nuclei Template was used.                         |
| CVE-2021-39226   | ✅           | Nuclei Template was used.                         |
| CVE-2021-39793   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-4034    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-40438   | ✅           | Nuclei Template was used.                         |
| CVE-2021-40444   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-40449   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-40450   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-40539   | ✅           | Nuclei Template was used.                         |
| CVE-2021-40870   | ✅           | Nuclei Template was used.                         |
| CVE-2021-4102    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-41357   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-41379   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-41773   | ✅           | Nuclei Template was used.                         |
| CVE-2021-42013   | ✅           | Nuclei Template was used.                         |
| CVE-2021-42237   | ✅           | Nuclei Template was used.                         |
| CVE-2021-42258   | ✅           | Nuclei Template was used.                         |
| CVE-2021-42278   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-42287   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-42292   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-42321   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-43890   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-44026   | ❌           | Missing public exploit.                           |
| CVE-2021-44077   | ✅           | Nuclei Template was used.                         |
| CVE-2021-44168   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2021-44228   | ✅           | Nuclei Template was used.                         |
| CVE-2021-44515   | ✅           | Nuclei Template was used.                         |
| CVE-2021-45046   | ✅           | Nuclei Template was used.                         |
| CVE-2021-45382   | ✅           | Added to Asteroid.                                |
| CVE-2022-0028    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-0543    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-0609    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-0847    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-1040    | ✅           | Nuclei Template was used.                         |
| CVE-2022-1096    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-1364    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-1388    | ✅           | Nuclei Template was used.                         |
| CVE-2022-20699   | ✅           | Metasploit module was used.                       |
| CVE-2022-20700   | ❌           | Missing public exploit.                           |
| CVE-2022-20701   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-20703   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-20708   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-21587   | ✅           | Nuclei Template was used.                         |
| CVE-2022-21882   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-21919   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-21971   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-21999   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22047   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22265   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22536   | ✅           | Nuclei Template was used.                         |
| CVE-2022-22587   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22620   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22674   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22675   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22706   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22718   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22947   | ✅           | Nuclei Template was used.                         |
| CVE-2022-2294    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22954   | ✅           | Nuclei Template was used.                         |
| CVE-2022-22960   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-22963   | ✅           | Nuclei Template was used.                         |
| CVE-2022-22965   | ✅           | Nuclei Template was used.                         |
| CVE-2022-23131   | ✅           | Nuclei Template was used.                         |
| CVE-2022-23134   | ✅           | Nuclei Template was used.                         |
| CVE-2022-23176   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-24086   | ❌           | Missing public exploit.                           |
| CVE-2022-24112   | ✅           | Nuclei Template was used.                         |
| CVE-2022-24521   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-24682   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-24706   | ✅           | Nuclei Template was used.                         |
| CVE-2022-24990   | ✅           | Nuclei Template was used.                         |
| CVE-2022-26134   | ✅           | Nuclei Template was used.                         |
| CVE-2022-26138   | ✅           | Nuclei Template was used.                         |
| CVE-2022-26143   | ✅           | Nuclei Template was used.                         |
| CVE-2022-26258   | ❌           | Authentication Required .                         |
| CVE-2022-26318   | ✅           | Added to Asteroid.                                |
| CVE-2022-26352   | ✅           | Nuclei Template was used.                         |
| CVE-2022-26485   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26486   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26500   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26501   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26904   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26923   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-26925   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-27518   | ❌           | Missing public exploit.                           |
| CVE-2022-27593   | ✅           | Nuclei Template was used.                         |
| CVE-2022-27924   | ❌           | Missing public exploit.                           |
| CVE-2022-27925   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-27926   | ✅           | Nuclei Template was used.                         |
| CVE-2022-2856    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-28810   | ✅           | Metasploit module was used.                       |
| CVE-2022-28958   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-29303   | ✅           | Nuclei Template was used.                         |
| CVE-2022-29464   | ✅           | Nuclei Template was used.                         |
| CVE-2022-29499   | ✅           | Nuclei Template was used.                         |
| CVE-2022-30190   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-30333   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-3038    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-30525   | ✅           | Nuclei Template was used.                         |
| CVE-2022-3075    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-31199   | ❌           | Missing public exploit.                           |
| CVE-2022-3236    | ❌           | Missing public exploit.                           |
| CVE-2022-32893   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-32894   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-32917   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-33891   | ✅           | Nuclei Template was used.                         |
| CVE-2022-34713   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-35405   | ✅           | Nuclei Template was used.                         |
| CVE-2022-35914   | ✅           | Nuclei Template was used.                         |
| CVE-2022-36537   | ✅           | Nuclei Template was used.                         |
| CVE-2022-36804   | ✅           | Nuclei Template was used.                         |
| CVE-2022-37042   | ✅           | Nuclei Template was used.                         |
| CVE-2022-3723    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-37969   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-38181   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-39197   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-40139   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-40684   | ✅           | Nuclei Template was used.                         |
| CVE-2022-40765   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41033   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41040   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41049   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41073   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41080   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41082   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41091   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41125   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41128   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41223   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41328   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-41352   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2022-4135    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-42475   | ❌           | Memory corruption and needs a ROP chain.          |
| CVE-2022-4262    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-42827   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-42856   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-42948   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-44698   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2022-44877   | ✅           | Nuclei Template was used.                         |
| CVE-2022-46169   | ✅           | Nuclei Template was used.                         |
| CVE-2022-47966   | ✅           | Nuclei Template was used.                         |
| CVE-2022-47986   | ✅           | Nuclei Template was used.                         |
| CVE-2023-0266    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-0669    | ✅           | Nuclei Template was used.                         |
| CVE-2023-1389    | ✅           | Added to Asteroid.                                |
| CVE-2023-1671    | ⏳           |                                                   |
| CVE-2023-20109   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-20198   | ⏳           |                                                   |
| CVE-2023-20269   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-20273   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-2033    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-20867   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-20887   | ✅           | Nuclei Template was used.                         |
| CVE-2023-20963   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-2136    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21492   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21608   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21674   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21715   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21823   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-21839   | ✅           | Metasploit module was used.                       |
| CVE-2023-22515   | ✅           | Metasploit module was used.                       |
| CVE-2023-22518   | ✅           | Added to Asteroid.                                |
| CVE-2023-22952   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2023-23376   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-23397   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-23529   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-24489   | ✅           | Nuclei Template was used.                         |
| CVE-2023-24880   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-25717   | ✅           | Nuclei Template was used.                         |
| CVE-2023-26083   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-26359   | ✅           | Same nuclei template as CVE-2023-26360            |
| CVE-2023-26360   | ✅           | Nuclei Template was used.                         |
| CVE-2023-26369   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-27350   | ✅           | Nuclei Template was used.                         |
| CVE-2023-27532   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-27992   | ❌           | Missing public exploit.                           |
| CVE-2023-27997   | ✅           | Added to Asteroid.                                |
| CVE-2023-28204   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-28205   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-28206   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-28229   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-28252   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-28432   | ✅           | Nuclei Template was used.                         |
| CVE-2023-28434   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-2868    | ❌           | Call back needed .                                |
| CVE-2023-28771   | ❌           | Metasploit module without a check/check_code.     |
| CVE-2023-29298   | ✅           | Nuclei Template was used.                         |
| CVE-2023-29336   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-29492   | ❌           | Missing public exploit.                           |
| CVE-2023-29552   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-3079    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32046   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32049   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32315   | ✅           | Nuclei Template was used.                         |
| CVE-2023-32373   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32409   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32434   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32435   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-32439   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-33009   | ❌           | Missing public exploit.                           |
| CVE-2023-33010   | ❌           | Missing public exploit.                           |
| CVE-2023-33246   | ✅           | Nuclei Template was used.                         |
| CVE-2023-34362   | ✅           | Nuclei Template was used.                         |
| CVE-2023-35078   | ✅           | Nuclei Template was used.                         |
| CVE-2023-35081   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-3519    | ✅           | Metasploit module was used.                       |
| CVE-2023-35311   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-35674   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36025   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36033   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36036   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36563   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36584   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36761   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36802   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36844   | ✅           | Added to Asteroid.                                |
| CVE-2023-36845   | ✅           | Added to Asteroid.                                |
| CVE-2023-36846   | ✅           | Added to Asteroid.                                |
| CVE-2023-36847   | ✅           | Added to Asteroid.                                |
| CVE-2023-36851   | ✅           | Added to Asteroid.                                |
| CVE-2023-36874   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-36884   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-37450   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-37580   | ✅           | Nuclei Template was used.                         |
| CVE-2023-38035   | ✅           | Nuclei Template was used.                         |
| CVE-2023-38180   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-38205   | ✅           | Nuclei Template was used.                         |
| CVE-2023-38606   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-38831   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-40044   | ✅           | Metasploit module was used.                       |
| CVE-2023-41061   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41064   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41179   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41763   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41991   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41992   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-41993   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-4211    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-42793   | ✅           | Nuclei Template was used.                         |
| CVE-2023-42824   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-44487   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-46604   | ⏳           |                                                   |
| CVE-2023-46747   | ✅           | Nuclei Template was used.                         |
| CVE-2023-46748   | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-47246   | ⏳           |                                                   |
| CVE-2023-4863    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-4911    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-4966    | ✅           | Nuclei Template was used.                         |
| CVE-2023-5217    | ❌           | Not remotely exploitable/User interaction needed. |
| CVE-2023-5631    | ❌           | Not remotely exploitable/User interaction needed. |
