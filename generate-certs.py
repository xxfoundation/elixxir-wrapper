#!/usr/bin/env python3

#///////////////////////////////////////////////////////////////////////////////
#// Copyright © 2020 xx network SEZC                                          //
#//                                                                           //
#// Use of this source code is governed by a license that can be found in the //
#// LICENSE file                                                              //
#///////////////////////////////////////////////////////////////////////////////

# This file is an interactive script to generate certificates for both gateway and node

import os
import subprocess


def main():
    print("This script will ask you to input information to be used in key generation.")
    print("If you do not wish to enter any given field, a default will be provided, attributed to the xx network.")
    country = input("Country (default: 'KY (Cayman Islands)'): ")
    if country == "":
        country = 'KY'
    while len(country) != 2 or not country.isalpha():
        print("The country code entered must be exactly two letters")
        country = input("Country (default: 'KY (Cayman Islands)'): ")
    state = input("State/province (default: ' '): ")
    if state == "":
        state = " "
    locality = input("Locality (default: 'George Town'): ")
    if locality == "":
        locality = "George Town"
    organization = input("Organization (default: 'xxnetwork'): ")
    if organization == "":
        organization = "xxnetwork"
    organizational_unit = input("Organizational unit (default: 'nodes'): ")
    if organizational_unit == "":
        organizational_unit = "nodes"
    email = input("Email (default: 'admin@xx.network'): ")
    if email == "":
        email = "admin@xx.network"
    domain = input("Domain (default: 'xx.network'): ")
    if domain == "":
        domain = "xx.network"

    # write config opts to file
    f = open("cert.conf", 'a')
    f.write("""[req]
distinguished_name=req
[san]
subjectAltName=DNS:%s
""" % domain)
    os.chmod("cert.conf", 0o777)
    f.close()

    # Form full subject string
    if not os.path.exists('creds'):
        os.mkdir("creds")
    subj = "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s" % \
           (country, state, locality, organization, organizational_unit, domain, email)

    node = ["openssl", "req", "-new", "-newkey", "rsa:4096", "-x509", "-sha256", "-days", "730",
            "-nodes", "-keyout", "creds/node_key.key", "-out", "creds/node_cert.crt",
            "-subj", subj, "-extensions", "san", "-config", "cert.conf"]
    gate = ["openssl", "req", "-new", "-newkey", "rsa:4096", "-x509", "-sha256", "-days", "730",
            "-nodes", "-keyout", "creds/gateway_key.key", "-out", "creds/gateway_cert.crt",
            "-subj", subj, "-extensions", "san", "-config", "cert.conf"]
    subprocess.run(node)
    print("~~~~~")
    subprocess.run(gate)
    os.remove("cert.conf")


if __name__ == "__main__":
    main()
