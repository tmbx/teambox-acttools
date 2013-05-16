#
# Copyright (C) 2010-2012 Opersys inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Original cliadm command set.

import sys, shutil, ConfigParser

from kreadline import Command
from acttools import KAP, Workdir
from config import ClientConfig, AdminConfig, ClientManager, KeyConsistencyException
from misc import *
from kctllib.kkeys import *

# kpython
from kfile import *
from krun import *

# Reworked commands

class CdCommand(Command):
    Name = "cd"
    Syntax = "[<kdn>]"
    Help = "Select a client in the database."
    MaxParams = 1
    MinParams = 0

    def run(self, intr, kdn = None):
        if not kdn or kdn == ".":
            intr.client_conf = None
            intr.prompt = "> "
            return 0
        if kdn in intr.climgr:
            intr.client_conf = ClientConfig(intr.admin_conf, kdn)
            intr.prompt = "%s> " % kdn
            return 0
        else:
            sys.stderr.write("Client %s does not exists.\n" % kdn)
            return 1

class ShowConfCommand(Command):
    Name = "showconf"
    Syntax = ""
    Help = "Show the program configuration."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        print "Teambox SSL certificate:  " + intr.admin_conf.teambox_ssl_cert_path
        print "Teambox SSL key:          " + intr.admin_conf.teambox_ssl_key_path
        print "Teambox email secret key: " + intr.admin_conf.teambox_email_skey_path
        print "Key ID map:                " + intr.admin_conf.key_id_map_path
        print "Client database:           " + intr.admin_conf.client_db_path
        print "Trusted CA:                " + intr.admin_conf.trusted_ca_path
        print "KPS free bundle:           " + intr.admin_conf.bundle_path
        return 0

class LsCommand(Command):
    Name = "ls"
    Syntax = "<kdn> [<kdn>*]"
    Help = "Print the status of the current/specified clients."
    MaxParams = None
    MinParams = 0

    def _ls_internal(self, client_conf):
        print "KDN:               %s" % (client_conf.kdn)
        print "Organization:      %s" % (client_conf.org_name)

        kar_line = "KAR status:        "
        if client_conf.kar_exists():
            kar_line += "present"
            if client_conf.kar_open: kar_line += ", open"
            if client_conf.kar_verified: kar_line += ", verified"
        else:
            kar_line += "none"
        print kar_line

        collab_line = "Collab. access:    "
        if client_conf.uses_apps:
            collab_line += "on"
        else:
            collab_line += "off"
        print collab_line

        reseller_line = "Is reseller:       "
        if client_conf.is_reseller:
            reseller_line += "on"
        else:
            reseller_line += "off"
        print reseller_line

        lic_dates_line = "Best after/before: "
        if client_conf.best_after and client_conf.best_before:
            lic_dates_line += client_conf.best_after + " to " + client_conf.best_before
        else:
            lic_dates_line += "Unknown"
        print lic_dates_line

        lic_seats_line = "Seats lim/max:     "
        if client_conf.lim_seats and client_conf.max_seats:
            lic_seats_line += str(client_conf.lim_seats) + " / " + str(client_conf.max_seats)
        else:
            lic_seats_line += "Unknown"
        print lic_seats_line

        print "\nDomains:"
        for domain in client_conf.domains(): print domain

        print "\nKeys:"
        client_conf.print_key_status()

        if client_conf.email_key_exist():
            try:
                client_conf.check_key_consistency()
            except KeyConsistencyException, e:
                print "Warning: %s." % str(e)

    def run(self, intr, kdns = None):
        # No argument: show the information about the current client.
        if not kdns or len(kdns) == 0:
            if intr.client_conf == None:
                sys.stderr.write("No client selected.\n")
                return 1

            self._ls_internal(intr.client_conf)

        # Show the information about each specified client.
        else:
            need_newline = 0

            for kdn in kdns:
                if need_newline: print ""

                if kdn in intr.climgr:
                    sys.stderr.write("Client '%s' does not exist.\n" % i)
                    continue
                else:
                    self._ls_internal(intr.climgr[kdn])

                need_newline = 1
        return 0

class LsClientCommand(Command):
    Name = "lsclient"
    Syntax = ""
    Help = "List the clients in the database."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        # Keep a copy of the current client_conf while we process the clients.
        cached_client_conf = intr.client_conf

        print("KDN                    Organization Name")
        print("----------------------------------------")

        for cli in intr.climgr:
            sys.stdout.write(cli.kdn.ljust(22) + " " + cli.org_name + "\n")
        return 0

class AddClientCommand(Command):
    Name = "addclient"
    Syntax = "<kdn> [<preconfiguration .ini>]"
    Help = "Add a client to the database."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, kdn, preconfig_ini = None):
        if preconfig_ini and preconfig_ini != "@stdin" and not os.path.exists(preconfig_ini):
            sys.stderr.write("File %s not found.\n" % preconfig_ini)
            return 1
        if kdn in intr.climgr:
            sys.stderr.write("Client %s already exists.\n" % kdn)
            return 1
        
        newclient = intr.climgr.add(kdn)

        # Preconfigure the client with an .ini file.
        if preconfig_ini:
            # Select the client.
            r = intr.run_command(["cd", kdn])
            if r != 0: return r

            cfg = ConfigParser.ConfigParser()
            if preconfig_ini == "@stdin":
                cfg.readfp(sys.stdin)
            else:
                cfg.readfp(open(preconfig_ini, "r"))

            # Organization name
            r = intr.run_command(["setorgname", cfg.get("config", "org")])
            if r != 0: return r

            # Domains
            for i in cfg.get("config", "domains").split(" "):
                if i.strip():
                    r = intr.run_command(["newdomain", i])
                    if r != 0: return r

            # License data
            r = intr.run_command(["setseats", cfg.get("config", "seats_lim"), cfg.get("config", "seats_max")])
            if r != 0: return r

            r = intr.run_command(["setdates", cfg.get("config", "best_after"), cfg.get("config", "best_before")])
            if r != 0: return r

            # Reseller
            r = intr.run_command(["setreseller", cfg.get("config", "reseller")])
            if r != 0: return r

            # Collaboration
            r = intr.run_command(["setapps", cfg.get("config", "collaboration")])
            if r != 0: return r

        return 0

class RmClientCommand(Command):
    Name = "rmclient"
    Syntax = "[<kdn>]"
    Help = "Remove a client from the database."
    MaxParams = 1
    MinParams = 0

    def run(self, intr, kdn = None):
        if not kdn and not intr.client_conf:
            sys.stderr.write("No client selected.\n")
        elif not kdn and intr.client_conf:
            kdn = intr.client_conf.kdn
            intr.client_conf = None
            intr.prompt = "> "
        elif not kdn in intr.climgr:
            sys.stderr.write("Client %s does not exist.\n" % (kdn))
            return 1

        if intr.admin_conf.enable_confirm:
            if not get_confirm("Are you sure you want to remove client %s?" % (kdn), intr.assume_answer):
                return 1

        del intr.climgr[kdn]
        return 0

class SetOrgNameCommand(Command):
    Name = "setorgname"
    Syntax = "<name>"
    Help = "Set the name of the organization. Update name in keys."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, name):
        if not intr.client_conf:
            sys.stderr.write("No client selected.\n")
            return 1

        intr.client_conf.org_name = name
        return 0

class RmDomainCommand(Command):
    Name = "rmdomain"
    Syntax = "<domain>"
    Help = "Remove a domain from the domain list."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, domain):
        if not intr.client_conf:
            sys.stderr.write("No client selected.\n")
            return 1

        intr.client_conf.del_domain(domain)
        return 0

class NewDomainCommand(Command):
    Name = "newdomain"
    Syntax = "<domain>"
    Help = "Add a domain to the domain list."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, domain):
        if not intr.client_conf:
            sys.stderr.write("No client selected.\n")
            return 1

        intr.client_conf.add_domain(domain)
        return 0

class MvClientCommand(Command):
    Name = "mvclient"
    Syntax = "<old KDN> <new KDN>"
    Help = "Rename a client in the database."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, old_kdn, new_kdn):
        if not old_kdn in intr.climgr:
            sys.stderr.write("Client %s does not exist.\n" % (old_kdn))
            return 1
        if new_kdn in intr.climgr:
            sys.stderr.write("Client %s already exists.\n" % (new_kdn))
            return 1
        if not get_confirm("Are you sure you want to rename client %s as %s?" % (old_kdn, new_kdn), intr.assume_answer):
            return 1

        cli = intr.climgr[old_kdn]

        # Clear the selected client if it is being moved.
        if intr.client_conf and old_kdn == intr.client_conf.kdn:
            intr.client_conf = None

        cli.rename(new_kdn)
        return 0

class SetAppsCommand(Command):
    Name = "setapps"
    Syntax = "<on/off>"
    Help = "Determine if the license should allow the user to use applications."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, status):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1

        if status == "on":
            intr.client_conf.uses_apps = 1
        elif status == "off":
            intr.client_conf.uses_apps = 0
        else:
            sys.stderr.write("The application usage status must be 'off' or 'on'.\n")
            return 1

        return 0

class SetResellerCommand(Command):
    Name = "setreseller"
    Syntax = "<on/off>"
    Help = "Set the reseller status."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, status):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1

        if status == "on":
            intr.client_conf.is_reseller = 1
        elif status == "off":
            intr.client_conf.is_reseller = 0
        else:
            sys.stderr.write("The reseller status must be 'off' or 'on'.\n");
            return 1

        return 0

class SetLicenseDatesCommand(Command):
    Name = "setdates"
    Syntax = "<best after> <best before>"
    Help = "Set the numbers of seats."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, best_after, best_before):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1

        intr.client_conf.best_after = best_after
        intr.client_conf.best_before = best_before

        return 0

class SetLicenseSeatsCommand(Command):
    Name = "setseats"
    Syntax = "<lim seats> <max seats>"
    Help = "Set the numbers of seats for the license."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, lim_seats, max_seats):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1

        intr.client_conf.lim_seats = int(lim_seats)
        intr.client_conf.max_seats = int(max_seats)

        return 0

class AddKeyIDCommand(Command):
    Name = "addkeyid"
    Syntax = "<kdn> <key id>"
    Help = "Map a key ID to a KDN."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, kdn, key_id):
        key_id = int(key_id)

        if not intr.admin_conf.is_valid_key_id(key_id):
            sys.stderr.write("%s is not a valid key value.\n" % (key_id))
            return 1

        intr.admin_conf.KeyMap.add(key_id, kdn)
        return 0

class LsKeyIDCommand(Command):
    Name = "lskeyid"
    Syntax = ""
    Help = "List the key ID mappings."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        for k in intr.admin_conf.KeyMap:
            (key_id, key_owner) = k
            sys.stdout.write("%.20d: %s\n" % (key_id, key_owner))
        return 0

class RmKeyIDCommand(Command):
    Name = "rmkeyid"
    Syntax = "<key ID>"
    Help = "Delete a key ID mapping."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, key_id):
        key_id = int(key_id)

        if not intr.admin_conf.is_valid_key_id(key_id):
            sys.stderr.write("%s is not a valid key value.\n" % (key_id))
            return 1

        intr.admin_conf.KeyMap.remove_key(key_id_int)
        return 0

class SetKARCommand(Command):
    Name = "setkar"
    Syntax = "<kar file> [openkar] [vcert]"
    Help = "Import the Teambox Activation Request file."
    MaxParams = 3
    MinParams = 1

    def run(self, intr, kar, openkar = None, vcert = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if kar != "@stdin" and not os.path.isfile(kar):
            sys.stderr.write("%s is not a regular file.\n" % (kar))
            return 1
        if openkar and openkar != "openkar":
            sys.stderr.write("Invalid second argument. Must be openkar.\n")
            return 1
        if vcert and vcert != "vcert":
            sys.stderr.write("Invalid third argument. Must be vcert.\n")
            return 1
        if intr.client_conf.kar_exists():
            if not get_confirm("There is already a KAR for this client. Continue anyway?", intr.assume_answer):
                return 1

        intr.client_conf.kar_open = 0
        intr.client_conf.kar_verified = 0
        intr.client_conf.write_config()

        try:
            if kar != "@stdin":
                intr.client_conf.set_kar(read_file(kar))
            else:
                intr.client_conf.set_kar(sys.stdin.read())

            # Run the openkar and vcert commands immediately if the
            # user has asked so.
            if openkar:
                r = intr.run_command(["openkar"])
                if r != 0: return r
            if vcert:
                r = intr.run_command(["vcert"])
                if r != 0: return r

            return 0

        except Exception, e:
            if intr.debug: raise
            else:
                raise Exception("cannot set KAR: %s" % str(e))

class OpenKARCommand(Command):
    Name = "openkar"
    Syntax = ""
    Help = "Decrypt and unpack the KAR."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.client_conf.kar_exists():
            sys.stderr.write("No KAR file for client.\n")
            return 1
        if intr.client_conf.kar_open:
            if not get_confirm("The KAR has already been opened. Continue anyway?", intr.assume_answer):
                return 1

        intr.client_conf.kar_open = 0
        intr.client_conf.kar_verified = 0
        intr.client_conf.write_config()

        try:
            kar = intr.client_conf.open_kar()

            # Same for the parent info file.
            if kar.parent_kdn:
                intr.client_conf.parent_kdn = kar.parent_kden
                parent_client_conf = ClientConfig(intr.client_conf.parent_kdn)
                parent_client_conf.read_config()

                # If that client is a parent, check if the parent is authorized to resell.
                if not parent_client_conf.is_reseller:
                    sys.stderr.write("Parent KDN %s is not authorized to resell services.\n"
                                     % intr.client_conf.parent_kdn)
                    return 1

        except Exception, e:
            if intr.debug:
                raise
            else:
                raise Exception("cannot open KAR: %s" % str(e))

        intr.client_conf.kar_open = 1
        intr.client_conf.write_config()
        return 0

class WizardCommand(Command):
    Name = "wizard"
    Syntax = ""
    Help = "Run the wizard to process a new client."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        intr.client_conf = None

        # We must enable confirmations even if run from the command line.
        intr.admin_conf.enable_confirm = 1

        print "\nYou have invoked the New Client Wizard."
        print "I'm going to ask you a bunch of questions to setup the new client."
        print "Please answer each question correctly, or you'll have to start over."
        print "You can hit CTRL-C at any time to stop the wizard."

        try:
            # Prompt for the KDN.
            while 1:
                kdn = wizard_prompt("\nWhat is the client's KDN?")
                if kdn: break
                print "Please enter a valid KDN."

            # Delete the client if it exists.
            if client_exist(intr, kdn):
                print "\nThis client already exists."
                intr.run_command(["rmclient", kdn])

            # Add the client.
            print "Adding the client to the database."
            intr.run_command(["addclient", kdn])

            print "Selecting the client."
            intr.run_command(["cd", kdn])

            # Prompt for the KAR.
            while 1:
                kar_path = wizard_prompt("\nWhere is the KAR file?")
                if os.path.isfile(kar_path): break
                print "Please specify a valid path."

            # Set the KAR path, open it, print the certificate, verify it.
            print "Copying the KAR file in the client's directory."
            intr.run_command(["setkar", kar_path])

            print "Unpackaging the KAR."
            intr.run_command(["openkar"])

            print "Printing the KAR's certificate.\n"
            intr.run_command(["lscert"])

            print "Printing the requester information.\n"
            intr.run_command(["lsinfo"])

            print "Verifying the KAR's certificate."
            intr.run_command(["vcert"])

            # Ask if everything is OK.
            print("")
            if not get_confirm("The certificate looks right to me. Do you accept it?"):
                print "Alright, aborting."
                return 0

            # Prompt for the organization name and set it.
            while 1:
                org_name = wizard_prompt("\nWhat is the organization's name?")
                if org_name: break
                print "Please enter a valid organization name."

            print "Setting the organization name, updating encryption key name."
            intr.run_command(["setorgname", org_name])

            # Generate the key ID.
            print "Generating the key ID."
            key_id_str = str(intr.admin_conf.KeyMap.find_random_key_id())
            intr.run_command(["addkeyid", kdn, key_id_str])

            # Generate the signature keys.
            print "Generating the signature key pair."
            intr.run_command(["gensigkeys", key_id_str])

            # Update the encryption key ID.
            print "Updating the ID of the public encryption key."
            intr.run_command(["setenckeyid", key_id_str])

            # Prompt for the domains.
            print "\nEnter each domain on a line. Finish with an empty line."
            while 1:
                domain = wizard_prompt("Domain:")
                if not domain: break
                intr.run_command(["newdomain", domain])

            # Input the license information for the client.
            input_license_info(intr)

            # Generate the KAP, and the KOS & web server packages.
            print "Generating the KAP."
            intr.run_command(["genkap", os.path.join(intr.client_conf.path, "kap_activation.bin")])

            print "Generating the KOS package."
            intr.run_command(["genkos"])

            # Ask if the KOS package should be pushed now.
            if get_confirm("Do you want to push the KOS package on the KOS?"):
                intr.run_command(["pushkos"])

            print "\nI'm done, see you later."

        except KeyboardInterrupt, e:
            print "Wizard interrupted."
            if intr.debug: raise

        except Exception, e:
            if intr.debug: raise
            print "Wizard failed: %s" % str(e)

        return 0

class SetSigKeyIDCommand(Command):
    Name = "setsigkeyid"
    Syntax = "<key id>"
    Help = "Set the ID of the signature keys."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, key_id):
        key_id = int(key_id)

        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.admin_conf.is_valid_key_id(key_id):
            sys.stderr.write("%s is not a valid key value.\n" % (key_id))
            return 1

        if not intr.client_conf.get_sig_skey() or not intr.client_conf.get_sig_pkey():
            sys.stderr.write("The signature key pair does not exist.\n")
            return 1

        try:
            intr.client_conf.get_sig_pkey().setkeyid(key_id)
            intr.client_conf.get_sig_skey().setkeyid(key_id)
            return 0

        except Exception, e:
            if intr.debug:
                raise
            else:
                raise Exception("cannot change key ID: %s" % str(e))

class SetEncKeyIDCommand(Command):
    Name = "setenckeyid"
    Syntax = "<key ID>"
    Help = "Set the ID of the encryption key."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, key_id):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.admin_conf.is_valid_key_id(key_id):
            sys.stderr.write("%s is not a valid key value.\n" % (key_id))
            return 1

        if not intr.client_conf.get_enc_pkey():
            sys.stderr.write("The encryption key does not exist.\n")
            return 1

        try:
            intr.client_conf.get_enc_pkey().setkeyid(key_id)
            return 0

        except Exception, e:
            if intr.debug:
                raise
            else:
                raise Exception("cannot change key ID: %s" % str(e))

class VCertCommand(Command):
    Name = "vcert"
    Syntax = ""
    Help = "Verify the integrity of the KAR's certificate."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.client_conf.kar_open:
            sys.stderr.write("There is no KAR open for this client.\n")
            return 1

        intr.client_conf.kar_verified = 0
        intr.client_conf.write_config()

        # The 'verifyorgcert' program prints the appropriate success / error string
        # itself.
        kar_cert = intr.client_conf.open_kar().cert
        show_cmd_output(["verifyorgcert",
                         "-o", kar_cert.as_path(),
                         "-d", intr.admin_conf.trusted_ca_path,
                         "-v"])

        intr.client_conf.kar_verified = 1
        intr.client_conf.write_config()
        return 0

def cmd_list_cert_internal(client_conf, print_option):
    if client_conf == None:
        sys.stderr.write("No client selected.\n")
        return 1
    if not client_conf.kar_open:
        sys.stderr.write("There is no KAR open for this client.\n")
        return 1
    kar_cert = client_conf.open_kar().cert
    print get_cmd_output(("verifyorgcert", "-o", kar_cert.as_path(), print_option))
    return 0

class LsCertCommand(Command):
    Name = "lscert"
    Syntax = ""
    Help = "Print the content of the certificate (short format)."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        return cmd_list_cert_internal(intr.client_conf, '-p')

class LlCertCommand(Command):
    Name = "llcert"
    Syntax = ""
    Help = "Print the content of the certificate (long format)."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        return cmd_list_cert_internal(intr.client_conf, '-P')

class LsInfoCommand(Command):
    Name = "lsinfo"
    Syntax = ""
    Help = "Print the information about the requester."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.client_conf.kar_exists():
            sys.stderr.write("No KAR file for client.\n")
            return 1

        # Check if the info file exists, and if so, just dump it.
        kar = intr.client_conf.open_kar()
        if kar.info: print kar.info
        return 0

class SetKeysCommand(Command):
    Name = "setkeys"
    Syntax = "<key id> <public signature key> <private signature key>"
    Help = "Use pre-generated key for a client."
    MaxParams = 3
    MinParams = 2

    def run(self, intr, key_id, sig_pkey, sig_skey = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1

        # Add the key ID
        r = intr.run_command(["addkeyid", intr.client_conf.kdn, key_id])
        if r != 0: return r

        # Set the encryption key ID
        intr.run_command(["setenckeyid", key_id])

        # Save the keys.
        if sig_pkey != "@stdin":
            # FIXME: We don't need that in practice for now.
            sys.stderr.write("Unimplemented for now.")
            return 1
        else:
            (sig_pkey_data, sig_skey_data) = sys.stdin.read().split("@")
            sig_pkey_kkey = Key.fromBuffer(sig_pkey_data)
            sig_skey_kkey = Key.fromBuffer(sig_skey_data)
            sig_pkey_kkey.setkeyid(key_id)
            sig_skey_kkey.setkeyid(key_id)
            sig_pkey_kkey.setkeyname(intr.client_conf.org_name)
            sig_skey_kkey.setkeyname(intr.client_conf.org_name)
            intr.client_conf.set_sig_pkey(sig_pkey_kkey)
            intr.client_conf.set_sig_skey(sig_skey_kkey)
            return 0

class GenKeysCommand(Command):
    Name = "genkeys"
    Syntax = ""
    Help = "Generate signature key and setup key ID."
    MaxParams = 0
    MinParams = 0

    def run(self, intr):
        # Generate a random key ID.
        key_id_str = str(intr.admin_conf.KeyMap.find_random_key_id())

        r = intr.run_command(["addkeyid", intr.client_conf.kdn, key_id_str])
        if r != 0: return r

        # Generate the signature keys with that key ID.
        intr.run_command(["gensigkeys", key_id_str])
        if r != 0: return r

        # Set the encryption key ID
        intr.run_command(["setenckeyid", key_id_str])
        if r != 0: return r

        return 0

class GenSigKeysCommand(Command):
    Name = "gensigkeys"
    Syntax = "<key ID>"
    Help = "Generate a signature key pair with this ID."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, key_id):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.admin_conf.is_valid_key_id(key_id):
            sys.stderr.write("%s is not a valid key value.\n" % (key_id))
            return 1
        if not intr.client_conf.org_name:
            sys.stderr.write("The organization name is not set.\n")
            return 1

        if intr.client_conf.get_sig_pkey() and \
           not get_confirm("The signature key pair already exists. Overwrite?", intr.assume_answer): return 1

        try:
            (pkey, skey) = Key.newPair("sig", key_id, intr.client_conf.org_name)
            intr.client_conf.set_sig_skey(skey)
            intr.client_conf.set_sig_pkey(pkey)
            return 0

        except Exception, e:
            if intr.debug:
                raise
            else:
                raise Exception("cannot generate keys: %s" % str(e))

class LsKAPCommand(Command):
    Name = "lskap"
    Syntax = ""
    Help = "List the KAP generated for the client."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1

        try:
            pass
        except Exception, e:
            if intr.debug: raise

class GenKAPCommand(Command):
    Name = "genkap"
    Syntax = "<output path> [unstable]"
    Help = "Generate the Teambox Activation Package."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, kap_path, bundle_type = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not intr.client_conf.org_name:
            sys.stderr.write("The organization name is not set.\n")
            return 1
        if not intr.client_conf.kar_open:
            sys.stderr.write("The KAR has not been opened.\n")
            return 1
        if not intr.client_conf.kar_verified:
            sys.stderr.write("The KAR has not been verified.\n")
            return 1
        if bundle_type and not bundle_type == 'unstable':
            sys.stderr.write("Invalid second argument. Must be 'unstable'.\n")
            return 1

        try:
            intr.client_conf.check_key_consistency()
        except KeyConsistencyException, e:
            sys.stderr.write("Inconsistent keys: %s.\n" % str(e))
            return 1

        try:
            if bundle_type == 'unstable':
                kap_data = intr.client_conf.new_kap(unstable_bundle = True)
            else:
                kap_data = intr.client_conf.new_kap()

            if kap_data:
                if not intr.assume_answer:
                    print "The following data will be generated and encrypted:"
                    print KAP.show_KAP(kap_data)

                fd = None
                p = None
                if kap_path == "@stdout":
                    (fd, p) = tempfile.mkstemp()
                else:
                    p = kap_path

                if get_confirm("Do you want to save this KAP?", intr.assume_answer):
                    kap_id = intr.client_conf.save_kap(kap_data)
                    intr.client_conf.encrypt_kap(kap_id, p)
                    if kap_path != "@stdout":
                        print "Saved and encrypted KAP %s to %s" % (kap_id, kap_path)
                    else:
                        os.close(fd)
                        sys.stdout.write(read_file(p))
                        os.unlink(p)

            return 0

        except Exception, e:
            if intr.debug: raise
            else: raise Exception("cannot generate KAP: %s" % str(e))

class GenLicenseKAPCommand(Command):
    Name = "genlickap"
    Syntax = "<output path>"
    Help = "Generate the license file for the client."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, kap_path):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1
        if not intr.client_conf.kar_open:
            sys.stderr.write("The KAR has not been opened.\n"); return 1
        if not intr.client_conf.kar_verified:
            sys.stderr.write("The KAR has not been verified.\n"); return 1
        if not intr.client_conf.best_before or not intr.client_conf.best_after:
            sys.stderr.write("The license validity dates have not been set.\n"); return 1
        if not intr.client_conf.lim_seats or not intr.client_conf.max_seats:
            sys.stderr.write("The license seats counts have not been set.\n"); return 1

        try:
            kap_data = intr.client_conf.new_license_kap()

            if kap_data:
                print "The following data will be generated and encrypted:"
                print KAP.show_KAP(kap_data)

                if get_confirm("Do you want to save this KAP?", intr.assume_answer):
                    kap_id = intr.client_conf.save_kap(kap_data)
                    intr.client_conf.encrypt_kap(kap_id, kap_path)
                    print "Saved and encrypted KAP %s to %s" % (kap_id, kap_path)

            return 0

        except Exception, e:
            if intr.debug: raise
            else: raise Exception("cannot generate license KAP: %s" % str(e))

class GenUpdateKAPCommand(Command):
    Name = "genupkap"
    Help = "Generate Teambox Activation Package for upgrade."
    Syntax = "<output path>"
    MaxParams = 1
    MinParams = 1

    def run(self, intr, kap_path):
        client_conf = intr.client_conf

        if not intr.client_conf:
            sys.stderr.write("No client selected.\n")
            return 1

        # Check if the client license has been set.
        if not intr.client_conf.lim_seats or not intr.client_conf.max_seats:
            input_license_info(intr)

        # Prepare the client upgrade KAP.
        try:
            kap_data = intr.client_conf.new_upgrade_kap()

            if kap_data:
                print "The following data will be generated and encrypted:"
                print KAP.show_KAP(kap_data)

                if get_confirm("Do you want to save this KAP?", intr.assume_answer):
                    kap_id = intr.client_conf.save_kap(kap_data)
                    intr.client_conf.encrypt_kap(kap_id, kap_path)
                    print "Saved and encrypted KAP %s to %s" % (kap_id, kap_path)

            return 0

        except Exception, e:
            if intr.debug: raise
            else: raise Exception("cannot generate KAP: %s" % str(e))

class PushKOSCommand(Command):
    Name = "pushkos"
    Syntax = ""
    Help = "Push the client KOS package on the KOS."
    MaxParams = 0
    MinParams = 0

    def run(self, intr):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n")
            return 1
        if not os.path.isfile(intr.client_conf.kos_pkg_path):
            sys.stderr.write("The KOS package does not exist.\n")
            return 1

        try:
            get_cmd_output(("insertclient", intr.client_conf.kos_pkg_path))
            return 0

        except Exception, e:
            if intr.debug:
                raise
            else:
                raise Exception("cannot push client KOS package: %s" % str(e))

class GenKOSCommand(Command):
    Name = "genkos"
    Syntax = "[pushkos]"
    Help = "Generate the client KOS package."
    MaxParams = 1
    MinParams = 0

    def run(self, intr, pushkos = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1
        if not intr.client_conf.org_name:
            sys.stderr.write("The organization name is not set.\n"); return 1
        if pushkos and pushkos != "pushkos":
            sys.stderr.write("Invalid first argument. Must be pushkos.\n"); return 1

        try:
            intr.client_conf.check_key_consistency()
        except KeyConsistencyException, e:
            sys.stderr.write("Inconsistent keys: %s.\n" % str(e))
            return 1

        # Create the client_kos.tar.gz archive.
        try:
            workdir = Workdir()
            kos_dir = workdir.path() + "/client_kos/"
            os.mkdir(kos_dir)

            intr.client_conf.get_sig_pkey().save(kos_dir + "email.sig.pkey")
            intr.client_conf.get_sig_skey().save(kos_dir + "email.sig.skey")
            intr.client_conf.get_enc_pkey().save(kos_dir + "email.enc.pkey")
            shutil.copy(intr.client_conf.path + "config.ini", kos_dir + "config.ini")
            write_file(kos_dir + "kdn", intr.client_conf.kdn)
            write_file(kos_dir + "key_id", str(intr.client_conf.get_key_id()))

            tarzcvf = Popen(args = ["tar",
                                    "-zcvf",
                                    "client_kos.tar.gz",
                                    "client_kos"],
                            stdout = PIPE,
                            stderr = PIPE,
                            shell = False,
                            cwd = workdir.path())
            (_, err_text) = tarzcvf.communicate()
            if tarzcvf.returncode != 0:
                raise Exception("tar error: %s" % err_text.strip())

            shutil.copy(workdir.path() + "/client_kos.tar.gz", intr.client_conf.kos_pkg_path)
            workdir.close()

            # Push to the KOS if this was demanded.
            if pushkos:
                print "Pushing to KOS."
                r = intr.run_command(["pushkos"])
                if r != 0: return r

            return 0

        except Exception, e:
            if intr.debug: raise
            else: raise Exception("cannot generate KOS archive: %s" % str(e))

class LsKAPCommand(Command):
    Name = "lskap"
    Syntax = ""
    Help = "List the KAP registered to one client."
    MaxParams = 0
    MinParams = 0

    def run(self, intr, args = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1

        for kap in intr.client_conf.KapManager:
            sys.stdout.write(kap + "\n")
        return 0

class EncryptKAPCommand(Command):
    Name = "encryptkap"
    Syntax = "<kap ID> <output path>"
    Help = "Re-encrypt a previously generated KAP for a client."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, kap_id, kap_path):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1
        if not intr.client_conf.KapManager.exists(kap_id):
            sys.stderr.write("KAP %s doesn't exists for this client.\n" % kap_id); return 1

        try:
            kap_data = intr.client_conf.KapManager.get(kap_id)

            if kap_data:
                if not intr.assume_answer:
                    sys.stdout.write("The following data will be encrypted:")
                    sys.stdout.write(KAP.show_KAP(kap_data))

                if get_confirm("Do you want to save this KAP?", intr.assume_answer):
                    intr.client_conf.encrypt_kap(kap_id, kap_path)
                    sys.stdout.write("Saved KAP %s to %s" % (kap_id, kap_path))
            return 0

        except Exception, e:
            if intr.debug: raise
            else: raise Exception("Cannot encrypt KAP: %s" % str(e))

class ShowKAPCommand(Command):
    Name = "showkap"
    Syntax = "<kap ID>"
    Help = "Show the informations contained in a KAP file."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, kap_id):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1
        if not intr.client_conf.KapManager.exists(kap_id):
            sys.stderr.write("KAP %s doesn't exists for this client.\n" % kap_id); return 1

        kap_data = intr.client_conf.KapManager.get(kap_id)
        sys.stdout.write(KAP.show_KAP(kap_data))
        return 0

class SignCertCommand(Command):
    Name = "signcsr"
    Syntax = "<csr path> [<output>]"
    Help = "Sign a CSR with the Teambox certificate."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, csr, stdout = None):
        if intr.client_conf == None:
            sys.stderr.write("No client selected.\n"); return 1
        if csr and csr != "@stdin":
            if not os.path.exists(csr):
                sys.stderr.write("File %s does not exists.\n" % csr)
                return 1
        if stdout and stdout != "@stdout":
            sys.stderr.write("Invalid valid for output.\n"); return 1

        if csr == "@stdin":
            cert = intr.client_conf.CertManager.sign(sys.stdin.read())
        else:
            cert = intr.client_conf.CertManager.sign(read_file(csr))

        if stdout and stdout == "@stdout":
            sys.stdout.write(cert.as_data() + "\n")
        else:
            sys.stdout.write("Signed certificate in %s." % cert.as_path())
        return 0
