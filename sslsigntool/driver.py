#
# Copyright (C) 2010-2012 Opersys inc.
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License, not any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#!/usr/bin/python

import getopt, sys, os;
from subprocess import *;


# This function closes a file silently. No exception is thrown if an error
# occurs.
def silent_close_file(file):
    try:
       if file: file.close();
    except IOError:
       pass;


# This function executes the command specified. If a string is specified, the
# command is executed as a shell command, otherwise the first list element is
# expected to be the program name and the other elements are the arguments of
# the program.
# This function throws an exception on error.
def do_system(arg_list):
    cmd_str = "";
    shell = False;

    if (type(arg_list) == str):
        cmd_str = arg_list;
        shell = True;
    else:
        for arg in arg_list:
            if cmd_str != "":
                cmd_str += " ";

            cmd_str += arg;

    try:
        retcode = call(arg_list, shell=shell);
    except OSError, e:
        raise Exception("command '%s' failed: %s" % (cmd_str, e.args[1]));

    if retcode:
        raise Exception("command '%s' failed with code %d" % (cmd_str, retcode));

def generate_email_key(pub_path, priv_path):
    print("===> Generating customer email encryption key");

    try:
        pub_file = open(pub_path, "wb");
        pub_file.write("This is the public email encryption key. Share it around.\n");
        pub_file.close();

        priv_file = open(priv_path, "wb");
        priv_file.write("This is the private email encryption key. Keep it secret.\n");
        priv_file.close();
    except IOError, e:
        raise Exception("cannot generate customer email encryption keys: %s" % str(e));


class cik_info:
    def __init__(self, param_path=None, key_path=None, cert_path=None, country=None, state=None, city=None, org=None,
                 unit=None, cn=None, email=None, days=None):

        self.param_path = param_path;
        self.key_path = key_path;
        self.cert_path = cert_path;
        self.country = country;
        self.state = state;
        self.city = city;
        self.org = org;
        self.unit = unit;
        self.cn = cn;
        self.email = email;
        self.days = days;


def generate_cik_csr(cik):
    print("===> Generating customer installation CSR");
    #do_system(("openssl", "req", "-new", "-x509", "-keyout", "test/client/cik_key.pem", "-out", "test/client/cik.pem",
    #          "-days "));

    param_file = None;

    try:
        param_file = open(cik.param_path, "wb");
        param_file.write("[ req ]\n");
        param_file.write("distinguished_name = req_distinguished_name\n");
        param_file.write("prompt = no\n");
        param_file.write("\n");
        param_file.write("[ req_distinguished_name ]\n");

        # Beware: openssl chokes on empty attributes, or attributes that do not
        # have the expected length.
        if cik.country: param_file.write("C = %s\n" % cik.country);
        if cik.state: param_file.write("ST = %s\n" % cik.state);
        if cik.city: param_file.write("L = %s\n" % cik.city);
        if cik.org: param_file.write("O = %s\n" % cik.org);
        if cik.unit: param_file.write("OU = %s\n" % cik.unit);
        if cik.cn: param_file.write("CN = %s\n" % cik.cn);
        if cik.email: param_file.write("emailAddress = %s\n" % cik.email);
        param_file.close();

        do_system("openssl req -nodes -new -config %s -keyout %s -out %s -days %d"
                  % (cik.param_path, cik.key_path, cik.cert_path, cik.days));

    except Exception, e:
        silent_close_file(param_file);
        raise Exception("cannot generate CIK pair: %s" % str(e));


def sign_cik_csr(csr_path, cert_path):
    print("===> Signing customer installation CSR (mock step)");

    try:
        do_system(("openssl ca -in %s -out %s -cert test/ttp/ca_cert.pem -keyfile test/ttp/ca_key.pem " +
                   "-config test/ttp/openssl.cnf -batch") % (csr_path, cert_path));

    except Exception, e:
        raise Exception("cannot sign CSR: %s" % str(e));


def ensure_regular_file(path):
    if not os.path.isfile(path):
        raise Exception("%s is not a regular file" % path);


def prepare_kar_tarball(cik_cert_path, email_ek_pub_path, output_path, tmp_dir_path):
    print("===> Preparing Teambox activation request tarball");

    try:
        do_system("rm -rf %s" % tmp_dir_path);
        do_system("mkdir -p %s" % tmp_dir_path);
        do_system("mkdir -p %s/kar" % tmp_dir_path);
        do_system("cp %s %s/kar/cik_cert.pem" % (cik_cert_path, tmp_dir_path));
        do_system("cp %s %s/kar/email_ek.pub" % (email_ek_pub_path, tmp_dir_path));
        do_system("tar -C %s -zcvf %s kar" % (tmp_dir_path, output_path));
        do_system("rm -rf %s" % tmp_dir_path);

    except Exception, e:
        raise Exception("cannot create Teambox activation request tarball: %s" % str(e));


def sign_and_encrypt_kar_tarball(cik_key_path, cik_cert_path, kik_cert_path, tarball_path, output_path, tmp_dir_path):
    print("===> Signing and encrypting Teambox activation request tarball");

    try:
        do_system("rm -rf %s" % tmp_dir_path);
        do_system("mkdir -p %s" % tmp_dir_path);
        do_system("sha256sum %s | awk '{print $1}' > %s/kar_hash" % (tarball_path, tmp_dir_path));
        do_system("./sslsigntool sign %s %s %s/kar_hash %s/kar.sig"
                  % (cik_cert_path, cik_key_path, tmp_dir_path, tmp_dir_path));
        do_system("mv %s %s/kar.tar.gz" % (tarball_path, tmp_dir_path));

        # Use '-b 1' to prevent tar from wasting lots of memory.
        do_system("tar -b 1 -C %s -cvf %s/signed_kar.tar kar.tar.gz kar.sig" % (tmp_dir_path, tmp_dir_path));
        do_system("openssl smime -encrypt -binary -outform pem -aes256 -in %s/signed_kar.tar -out %s %s"
                  % (tmp_dir_path, output_path, kik_cert_path));
        do_system("rm -rf %s" % tmp_dir_path);

    except Exception, e:
        raise Exception("cannot sign and encrypt Teambox activation request tarball: %s" % str(e));


def decrypt_and_verify_kar_tarball(input_path, kik_key_path, kik_cert_path, output_path, tmp_dir_path):
    print("===> Decrypting and verifying Teambox activation request tarball");

    try:
        do_system("rm -rf %s" % tmp_dir_path);
        do_system("mkdir -p %s" % tmp_dir_path);
        do_system("openssl smime -decrypt -inform pem -in %s -out %s/signed_kar.tar -recip %s -inkey %s"
                  % (input_path, tmp_dir_path, kik_cert_path, kik_key_path));
        do_system("tar -C %s -xvf %s/signed_kar.tar kar.tar.gz kar.sig" % (tmp_dir_path, tmp_dir_path));
        ensure_regular_file("%s/kar.tar.gz" % tmp_dir_path);
        ensure_regular_file("%s/kar.sig" % tmp_dir_path);
        do_system("tar -C %s -zxvf %s/kar.tar.gz kar/cik_cert.pem" % (tmp_dir_path, tmp_dir_path));
        ensure_regular_file("%s/kar.sig" % tmp_dir_path);
        do_system("sha256sum %s/kar.tar.gz | awk '{print $1}' > %s/kar_hash" % (tmp_dir_path, tmp_dir_path));
        do_system("./sslsigntool verify %s/kar/cik_cert.pem %s/kar_hash %s/kar.sig"
                  % (tmp_dir_path, tmp_dir_path, tmp_dir_path));
        do_system("mv %s/kar.tar.gz %s" % (tmp_dir_path, output_path));
        do_system("rm -rf %s" % tmp_dir_path);

    except Exception, e:
        raise Exception("cannot decrypt and verify Teambox activation request tarball: %s" % str(e));


def prepare_kap_tarball(email_ik_priv_path, email_ik_pub_path, install_pkg_path, output_path, tmp_path):
    print("===> Preparing Teambox activation package tarball");

    try:
        do_system("rm -rf %s" % tmp_path);
        do_system("mkdir -p %s" % tmp_path);
        do_system("mkdir -p %s/kap" % tmp_path);
        do_system("cp %s %s/kap/email_ik.priv" % (email_ik_priv_path, tmp_path));
        do_system("cp %s %s/kap/email_ik.pub" % (email_ik_pub_path, tmp_path));
        do_system("cp %s %s/kap/install_pkg" % (install_pkg_path, tmp_path));
        do_system("tar -C %s -zcvf %s kap" % (tmp_path, output_path));
        do_system("rm -rf %s" % tmp_path);

    except Exception, e:
        raise Exception("cannot create Teambox activation package tarball: %s" % str(e));


def sign_and_encrypt_kap_tarball(cik_cert_path, kik_key_path, kik_cert_path, tarball_path, output_path, tmp_dir_path):
    print("===> Signing and encrypting Teambox activation package tarball");

    try:
        do_system("rm -rf %s" % tmp_dir_path);
        do_system("mkdir -p %s" % tmp_dir_path);
        do_system("sha256sum %s | awk '{print $1}' > %s/kap_hash" % (tarball_path, tmp_dir_path));
        do_system("./sslsigntool sign %s %s %s/kap_hash %s/kap.sig"
                  % (kik_cert_path, kik_key_path, tmp_dir_path, tmp_dir_path));
        do_system("mv %s %s/kap.tar.gz" % (tarball_path, tmp_dir_path));

        # Use '-b 1' to prevent tar from wasting lots of memory.
        do_system("tar -b 1 -C %s -cvf %s/signed_kap.tar kap.tar.gz kap.sig" % (tmp_dir_path, tmp_dir_path));
        do_system("openssl smime -encrypt -binary -outform pem -aes256 -in %s/signed_kap.tar -out %s %s"
                  % (tmp_dir_path, output_path, cik_cert_path));
        do_system("rm -rf %s" % tmp_dir_path);

    except Exception, e:
        raise Exception("cannot sign and encrypt Teambox activation package tarball: %s" % str(e));


def decrypt_and_verify_kap_tarball(input_path, cik_key_path, cik_cert_path, kik_cert_path, output_path, tmp_dir_path):
    print("===> Decrypting and verifying Teambox activation package tarball");

    try:
        do_system("rm -rf %s" % tmp_dir_path);
        do_system("mkdir -p %s" % tmp_dir_path);
        do_system("openssl smime -decrypt -inform pem -in %s -out %s/signed_kap.tar -recip %s -inkey %s"
                  % (input_path, tmp_dir_path, cik_cert_path, cik_key_path));
        do_system("tar -C %s -xvf %s/signed_kap.tar kap.tar.gz kap.sig" % (tmp_dir_path, tmp_dir_path));
        ensure_regular_file("%s/kap.tar.gz" % tmp_dir_path);
        ensure_regular_file("%s/kap.sig" % tmp_dir_path);
        do_system("sha256sum %s/kap.tar.gz | awk '{print $1}' > %s/kap_hash" % (tmp_dir_path, tmp_dir_path));
        do_system("./sslsigntool verify %s %s/kap_hash %s/kap.sig" % (kik_cert_path, tmp_dir_path, tmp_dir_path));
        do_system("mv %s/kap.tar.gz %s" % (tmp_dir_path, output_path));
        do_system("rm -rf %s" % tmp_dir_path);

    except Exception, e:
        raise Exception("cannot decrypt and verify Teambox activation package tarball: %s" % str(e));


def do_kar_simulation():
    generate_email_key("test/client/email_ek.pub", "test/client/email_ek.priv");

    cik = cik_info("test/client/cik_param.cnf", "test/client/cik_key.pem", "test/client/cik_csr.csr",
                   "ca", "qc", "Granby", "CCME", "Gadget", "ccme.com", "", 3650);
    generate_cik_csr(cik);

    sign_cik_csr("test/client/cik_csr.csr", "test/client/cik_cert.pem");

    prepare_kar_tarball("test/client/cik_cert.pem", "test/client/email_ek.pub", "test/client/kar.tar.gz",
                        "test/client/tmp");

    sign_and_encrypt_kar_tarball("test/client/cik_key.pem", "test/client/cik_cert.pem", "test/teambox/cert.pem",
                                 "test/client/kar.tar.gz", "test/client/encrypted_kar.bin", "test/client/tmp");

    decrypt_and_verify_kar_tarball("test/client/encrypted_kar.bin", "test/teambox/key.pem",
                                   "test/teambox/cert.pem", "test/teambox/kar.tar.gz", "test/teambox/tmp");


def do_kap_simulation():
    prepare_kap_tarball("test/teambox/email_ik.priv", "test/teambox/email_ik.pub", "test/teambox/install_pkg",
                        "test/teambox/kap.tar.gz", "test/teambox/tmp");

    sign_and_encrypt_kap_tarball("test/client/cik_cert.pem", "test/teambox/key.pem", "test/teambox/cert.pem",
                                 "test/teambox/kap.tar.gz", "test/teambox/encrypted_kap.bin", "test/teambox/tmp");

    decrypt_and_verify_kap_tarball("test/teambox/encrypted_kap.bin", "test/client/cik_key.pem",
                                   "test/client/cik_cert.pem", "test/teambox/cert.pem",
                                   "test/client/kap.tar.gz", "test/client/tmp");

def test():
    print("Testing.");

    try:
        do_kar_simulation();
        do_kap_simulation();

    except Exception, e:
        print("Error: %s." % (e));

    print("Done test.");


test();
