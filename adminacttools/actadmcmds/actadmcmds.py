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

# Commands for activation.
import sys, os, readline, acttools
import ConfigParser

# kpython
from kfile import *
from kreadline import Command

def dump_KAP(kap):
    l1 = ["Key ID: %s" % (str(kap.key_id) if not kap.key_id is None else "no"),
          "KDN: %s"    % (kap.kdn if not kap.kdn is None else "no")]
    l2 = ["Pub. Sig. Key: %s"  % ("yes" if not kap.email_sig_pkey is None else "no"),
          "Priv. Sig. Key: %s" % ("yes" if not kap.email_sig_skey is None else "no"),
          "Pub. Enc. Key: %s"  % ("yes" if not kap.email_enc_pkey is None else "no")]
    l3 = ["Bundle: %s"    % ("yes" if not kap.bundle is None else "no"),
          "License: %s"   % ("yes" if not kap.license is None else "no")]
    return [", ".join(l1), ", ".join(l2), ", ".join(l3)]

class LsActivatorCommand(Command):
    Name = "lsactivator"
    Syntax = ""
    Help = "List the activators."
    MaxParams = 0
    MinParams = 0

    def run(self, intr):
        acts = acttools.list_activators(intr.basedir)

        for act in acts:
            sys.stdout.write("%s\n" % act.name)

            is_invalid = False

            sys.stdout.write("\tIdentity: ")
            if act.identity:
                sys.stdout.write(act.identity.id_name + "\n")
            else:
                is_invalid = True
                sys.stdout.write("None or unknown.\n")

            if act.parent_identity:
                sys.stdout.write("\tParent identity: " + act.parent_identity.id_name + "\n")

            sys.stdout.write("\tKey set: ")
            if act.keyset:
                sys.stdout.write(act.keyset.keys_name + "\n")
            else:
                is_invalid = True
                sys.stdout.write("None.\n")

            if act.step:
                sys.stdout.write("\tStep number: %d\n" % act.step)

            if is_invalid:
                sys.stdout.write("\t*** This activator is invalid.\n")

            if act.identity and act.keyset:
                kaps = act.list_KAP()
                for k in kaps:
                    (kn, kap, _) = k
                    sys.stdout.write("\tKAP: %s\n" % kn)
                    lines = dump_KAP(kap)
                    for l in lines:
                        sys.stdout.write("\t\t%s\n" % l)
        return 0

class LsKeysCommand(Command):
    Name = "lskeys"
    Syntax = ""
    Help = "List the key sets."
    MaxParams = 0
    MinParams = 0

    def run(self, intr):
        def has_pair(k, n):
            skey = n + "_skey"
            pkey = n + "_pkey"
            has_skey = hasattr(k, skey) and not getattr(k, skey) is None
            has_pkey = hasattr(k, pkey) and not getattr(k, pkey) is None
            if has_skey and has_pkey:
                return "OK"
            elif not has_skey and not has_pkey:
                return "Missing"
            elif (has_skey and not has_pkey) or (not has_skey and has_pkey):
                return "Incomplete!"

        keysets = acttools.list_keys(intr.basedir)
        for k in keysets:
            sys.stdout.write("%s\n" % k.keys_name)
            sys.stdout.write("\tPre-activation keys: ")
            sys.stdout.write(has_pair(k, 'enc_zero') + "\n")
            sys.stdout.write("\tEncryption keys: ")
            sys.stdout.write(has_pair(k, 'enc') + "\n")
            sys.stdout.write("\tSignature keys: ")
            sys.stdout.write(has_pair(k, 'sig') + "\n")
        return 0

class LsIdentityCommand(Command):
    Name = "lsidentity"
    Syntax = ""
    Help = "List the identities on the disk."
    MaxParams = 0
    MinParams = 0

    def run(self, intr):
        identities = acttools.list_identity(intr.basedir)
        for ident in identities:
            sys.stdout.write("%s\n" % ident.id_name)
            z = (ident.country,
                 ident.state,
                 ident.location,
                 ident.org,
                 ident.org_unit,
                 ident.domain,
                 ident.email)
            sys.stdout.write("\t C: %s\n\t ST:%s\n\t L: %s\n\t O: %s\n\t OU:%s\n\t CN:%s\n\t @: %s\n" % z)
            z = (ident.admin_name, ident.admin_email)
            sys.stdout.write("\tAdmin: %s <%s>\n" % z)
            sys.stdout.write("\tKDN: %s\n" % (ident.kdn if not ident.kdn is None else "None"))
            if ident.asserted:
                sys.stdout.write("\t*** This identity has been asserted.\n")
            else:
                sys.stdout.write("\tThis identity has not been asserted.\n")
        return 0

class NewIdentityCommand(Command):
    Name = "newidentity"
    Syntax = "<identity name> [<identity .ini>]"
    Help = "Create a new identity for activation."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, id_name, identity_ini = None):
        if acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s already exists.\n" % id_name)
            return 1
        else:
            if identity_ini:
                if identity_ini != "@stdin" and not os.path.exists(identity_ini):
                    sys.stderr.write("File %s doesn't exists." % identity_ini)
                    return 1
                cfg = ConfigParser.ConfigParser()
                if identity_ini == "@stdin":
                    cfg.readfp(sys.stdin)
                else:
                    cfg.readfp(open(identity_ini, "r"))

                # Check if we have everything we need.
                for s in ["country", "state", "location", "org",
                          "org_unit", "domain", "name", "email"]:
                    if not cfg.has_option("identity", s):
                        sys.stdout.write("Missing %s in .ini file.\n" % s)
                        return 1

                ident = acttools.Identity(intr.basedir, id_name)
                ident.country = cfg.get("identity", "country")
                ident.state = cfg.get("identity", "state")
                ident.location = cfg.get("identity", "location")
                ident.org = cfg.get("identity", "org")
                ident.org_unit = cfg.get("identity", "org_unit")
                ident.domain = cfg.get("identity", "domain")
                ident.name = cfg.get("identity", "name")
                ident.email = cfg.get("identity", "email")
                ident.admin_name = cfg.get("identity", "name")
                ident.admin_email = cfg.get("identity", "email")
                ident.save()
            else:
                # Manually enter everything.
                ident = acttools.Identity(intr.basedir, id_name)
                ident.country = intr.simple_input("Country? ".rjust(15))
                ident.state = intr.simple_input("State? ".rjust(15))
                ident.location = intr.simple_input("Location? ".rjust(15))
                ident.org = intr.simple_input("Org.? ".rjust(15))
                ident.org_unit = intr.simple_input("Org. unit? ".rjust(15))
                ident.email = intr.simple_input("Email? ".rjust(15))
                ident.domain = intr.simple_input("Domain? ".rjust(15))
                ident.admin_name = intr.simple_input("Admin. name? ".rjust(15))
                ident.admin_email = intr.simple_input("Admin. email? ".rjust(15))
                ident.save()

        return 0

class NewActivatorCommand(Command):
    Name = "newactivator"
    Syntax = "<activator name> [<identity name>] [<keyset name>]"
    Help = "Create a new activation."
    MaxParams = 3
    MinParams = 1

    def run(self, intr, act_name, id_name = None, keys_name = None):
        if acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s already exists.\n" % act_name)
            return 1
        if id_name and not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % id_name)
            return 1
        if keys_name and not acttools.KeySet.exists(intr.basedir, keys_name):
            sys.stderr.write("Key set name %s doesn't exists.\n" % keys_name)
            return 1       

        act = acttools.Activator(intr.basedir, act_name)

        if id_name:
            ident = acttools.Identity(intr.basedir, id_name)
            act.identity = ident
        if keys_name:
            keys = acttools.KeySet(intr.basedir, keys_name)
            act.keyset = keys

        act.save()
        return 0

class ShowCSRCommand(Command):
    Name = "showcsr"
    Syntax = "<identity name>"
    Help = "Display the CSR to be used to assert the identity."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, id_name):
        if not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n")
            return 1
        else:
            ident = acttools.Identity(intr.basedir, id_name)
            sys.stdout.write(ident.get_CSR())
            return 0

class ShowCertCommand(Command):
    Name = "showcert"
    Syntax = "<identity name>"
    Help = "Display the certificate used to assert the identity."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, id_name):
        if not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % id_name)
            return 1
        else:
            ident = acttools.Identity(intr.basedir, id_name)
            sys.stdout.write(ident.get_cert())
            return 0

class SetCertCommand(Command):
    Name = "setcert"
    Syntax = "<identity name> <file name>"
    Help = "Set the certificate that asserts the identity."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, id_name, cert_file):
        if cert_file != "@stdin" and not os.path.exists(cert_file):
            sys.stderr.write("File %s doesn't exists.\n" % cert_file)
            return 1
        else:
            if cert_file == "@stdin":
                cert_data = sys.stdin.read()
            else:
                cert_data = read_file(cert_file)

        if not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % id_name)
            return 1
        else:
            ident = acttools.Identity(intr.basedir, id_name)
            ident.set_cert(cert_data)
            return 0

        if not ident.asserted:
            sys.stderr.write("This certificate doesn't assert this identity.\n")
            return 1

class SetParentIdentityCommand(Command):
    Name = "setparentidentity"
    Syntax = "<activator name> <identity name>"
    Help = "Set the parent identity to be used for signing a KAR."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, act_name, parent_id_name = None):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1
        if parent_id_name and not acttools.Identity.exists(intr.basedir, parent_id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % parent_id_name)
            return 1

        act = acttools.Activator(intr.basedir, act_name)
        if parent_id_name:
            ident = acttools.Identity(intr.basedir, parent_id_name)
            act.parent_identity = ident
        else:
            act.parent_identity = None

        act.save()
        return 0

class SetIdentityCommand(Command):
    Name = "setidentity"
    Syntax = "<activator name> <identity name>"
    Help = "Set the identity to be used for the activator."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, act_name, id_name = None):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1
        if id_name and not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % id_name)
            return 1

        act = acttools.Activator(intr.basedir, act_name)

        if id_name:
            ident = acttools.Identity(intr.basedir, id_name)
            act.identity = ident
        else:
            act.identity = None

        act.save()
        return 0

class SetKeysCommand(Command):
    Name = "setkeys"
    Syntax = "<activator name> <key set name>"
    Help = "Set the key set to be used for the activator."
    MaxParams = 2
    MinParams = 1

    def run(self, intr, act_name, keys_name = None):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1
        if keys_name and not acttools.KeySet.exists(intr.basedir, keys_name):
            sys.stderr.write("Key set name %s doesn't exists.\n" % keys_name)
            return 1

        act = acttools.Activator(intr.basedir, act_name)

        if keys_name:
            keys = acttools.KeySet(intr.basedir, keys_name)
            act.keyset = keys
        else:
            act.keyset = None

        act.save()
        return 0

class RmIdentityCommand(Command):
    Name = "rmidentity"
    Syntax = "<identity name>"
    Help = "Delete an existing identity."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, id_name):
        if not acttools.Identity.exists(intr.basedir, id_name):
            sys.stderr.write("Identity %s doesn't exists.\n" % id_name)
            return 1
        else:
            acttools.Identity(intr.basedir, id_name).delete()
            return 0

class RmKeysCommand(Command):
    Name = "rmkeys"
    Syntax = "<key set name>"
    Help = "Delete a set of keys."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, keys_name):
        if not acttools.KeySet.exists(intr.basedir, keys_name):
            sys.stderr.write("Key set %s doesn't exists.\n" % keys_name)
            return 1
        else:
            acttools.KeySet(intr.basedir, keys_name).delete()
            return 0

class RmActivatorCommand(Command):
    Name = "rmactivator"
    Syntax = "<activator name>"
    Help = "Remove an activator."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, act_name):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1

        act = acttools.Activator(intr.basedir, act_name)
        act.delete()
        return 0

class NewKeysCommand(Command):
    Name = "newkeys"
    Syntax = "<keys name> [<initial encryption pkey> <initial encryption skey>|@stdin]"
    Help = "Create new keys for a particular identity."
    MaxParams = 3
    MinParams = 1

    def run(self, intr, keys_name, zero_enc_pkey = None, zero_enc_skey = None):
        if acttools.KeySet.exists(intr.basedir, keys_name):
            sys.stdout.write("Key set %s already exists.\n" % keys_name)
            return 1
        else:
            zero_enc_pkey_data = zero_enc_skey_data = None            
            if zero_enc_pkey == "@stdin":
                # This is kind of a hack to support ractivate.
                (zero_enc_pkey_data, zero_enc_skey_data) = sys.stdin.read().split("@")
                acttools.KeySet(intr.basedir, keys_name,
                                zero_pkey_data = zero_enc_pkey_data,
                                zero_skey_data = zero_enc_skey_data)
            else:
                acttools.KeySet(intr.basedir, keys_name, 
                                zero_pkey_file = zero_enc_pkey, 
                                zero_skey_file = zero_enc_skey)
                return 0

class GenKARCommand(Command):
    Name = "genkar"
    Syntax = "<activator name> <kar output file>"
    Help = "Prepare a new KAR from the activator."
    MaxParams = 2
    MinParams = 2

    def run(self, intr, act_name, output_file):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1

        product_name = "unknown"
        product_version = "unknown"
        if os.path.exists("/etc/teambox/product_name"):
            product_name = read_file("/etc/teambox/product_name")
        if os.path.exists("/etc/teambox/product_version"):
            product_version = read_file("/etc/teambox/product_version")

        act = acttools.Activator(intr.basedir, act_name)
        if output_file == "@stdout":
            sys.stdout.write(act.get_KAR(product_name, product_version))
        else:
            write_file(output_file, act.get_KAR(product_name, product_version))
        return 0

class OpenKAPCommand(Command):
    Name = "openkap"
    Syntax = "<activator name> <kap file> [applykap]"
    Help = "Open a KAP file."
    MaxParams = 3
    MinParams = 2

    def run(self, intr, act_name, kap_file, applykap = None):
        if kap_file != "@stdin" and not os.path.exists(kap_file):
            sys.stderr.write("KAP file %s doesn't exists." % kap_file)
            return 1
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1
        if applykap and applykap != "applykap":
            sys.stderr.write("Invalid third argument. Must be applykap.")
            return 1

        act = acttools.Activator(intr.basedir, act_name)
        if kap_file != "@stdin":
            kap_id = act.add_KAP(read_file(kap_file))
        else:
            kap_id = act.add_KAP(sys.stdin.read())

        if applykap:
            r = intr.run_command(["applykap", act.name, kap_id])
            if r != 0: return r

        return 0

class LsKAPCommand(Command):
    Name = "lskap"
    Syntax = "<activator name>"
    Help = "List the KAP registered to an activator."
    MaxParams = 1
    MinParams = 1

    def run(self, intr, act_name):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1

        act = acttools.Activator(intr.basedir, act_name)
        kaps = act.list_KAP()

        if len(kaps) == 0: return 0
        for k in kaps:
            (kn, kap, _) = k
            sys.stdout.write("%s\n" % kn)
            lines = dump_KAP(kap)
            for l in lines:
                sys.stdout.write("\t%s\n" % l)
        return 0

class ApplyKAPCommand(Command):
    Name = "applykap"
    Syntax = "<activator name> <kap name> [test]"
    Help = "Apply actions inside the KAP."
    MaxParams = 3
    MinParams = 2

    def run(self, intr, act_name, kap_name, test = None):
        if not acttools.Activator.exists(intr.basedir, act_name):
            sys.stderr.write("Activator %s doesn't exists.\n" % act_name)
            return 1

        do_apply = True
        if test == "test":
            do_apply = False

        act = acttools.Activator(intr.basedir, act_name)
        act.apply_KAP(kap_name, do_apply)
        return 0
