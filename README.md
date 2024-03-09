# Simple TLS/SSL Audit Wrapper

hdySSL is part of a set of personal tools developed to cover robust simple checks and automation. This is a personal project for my personal workflow and may/may not receive updates and may/may not work. Who knows. :shrug:

## Description

hdySSL is a wrapper tool that calls on a set of SSL/TLS auditing tools to perform scans and testing against known misconfigurations and known vulnerabilities. I am not the author of the invoked tools and all credit goes to their hard work.I am not the author of the invoked tools and all credit goes to their hard work.

**Credits:**

 - https://github.com/drwetter/testssl.sh
 - https://github.com/rbsec/sslscan
 - https://github.com/nabla-c0d3/sslyze

The primary use for this tool is to automate and complete an assessment on the applications SSL/TLS configuration. It uses several tools to perform this in order to cover edge cases and then outputs the content from these tools to their respective files for your **manual review**.

It is a simple automation tool to ensure I cover the basics and nothing more.

![](https://i.imgur.com/CXtkRDC.png)

**Features**

- **OS-agnostic**:  Tool is **OS-agnostic** as the application is built for portability in mind and can be compiled natively for both Windows and Linux platforms. 
- **Docker Execution**: The application executes and uses only Docker containers, (or sets up the docker images for you) for each step thereby removing the need for further dependencies and installation steps in order to function. 
- Whatever features are part of the wrapped programs.
- Also, you can provide it a single URL or a list of URLs via feeding a .txt file.

## Requirements

Dependencies include the following to be installed prior to using this tool:

 - Docker
 - Git

## Installation

As always, review code before using public tools. Program is written in golang; you will need Go installed in order to compile. Code is very simple, and you can easily adjust to add your own comments, headers, and recommendations you want to keep track of.

```
$ git clone https://github.com/hdysec/hdy-ssl-scan.git
$ cd hdy-ssl-scan
$ go build .
```

## Usage

```
Usage:
hdySSL -d <domain>
hdySSL -D <domainlist.txt>

Usage:
  hdySSL [flags]

Flags:
  -d, --domain string       Provide the domain excluding the protocol (http/s://).
  -D, --domainList string   Provide the list of domain names excluding the protocol (http/s://).
  -h, --help                help for hdySSL

```

**Disclaimer**:

- Sharing because sharing is caring.
- Always review your local laws regarding use of tools that facilitate penetration testing and always seek permission before performing any testing on a client.


