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

import os, os.path, shutil, time, tempfile

from acttools import KAP, KAR, ssl
from kctllib.kkeys import Key

# kpython
from kfile import *
from krun import *

import ConfigParser

def GetUniquePath(target_dir, prefix, suffix = None):
    """Obtain a file name that is unique in a particular directory."""
    s = time.strftime("%Y%m%d")
    kn = ""
    kp = ""
    d = 1
    while True:
        kn = "%s_%s_%d" % (prefix, s, d)
        if suffix: kn += suffix
        kp = os.path.join(target_dir, kn)
        if not os.path.exists(kp):
            break
        else:
            d = d + 1
    return kp

class KeyConsistencyException(Exception):
    """This exception is thrown when a consistency error is detected
    in the keys configured for a client."""
    pass

class AdminKeyMap:
    """Global key map."""

    def __init__(self, key_map_file):
        self._map = {}
        self._map_file = key_map_file
        if not os.path.exists(self._map_file):
            key_id_parser = ConfigParser.ConfigParser()
            key_id_parser.add_section("key_id")
            f = open(self._map_file, "wb")
            key_id_parser.write(f)
            f.close()
        self._load()

    def _save(self):
        parser = ConfigParser.ConfigParser()
        parser.add_section("key_id")
        for key_id in self._map:
            parser.set("key_id", str(key_id), self._map[key_id])
        f = open(self._map_file, "wb")
        parser.write(f)
        f.close()

    def _load(self):
        self._map = {}
        parser = ConfigParser.ConfigParser()
        parser.readfp(open(self._map_file))
        key_id_list = parser.items("key_id")
        for pair in key_id_list:
            self._map[int(pair[0])] = pair[1]

    def add(self, key, kdn):
        self._map[key] = kdn
        self._save()

    def remove_key(self, key):
        if key in self._map:
            del self._map
            self._save()

    def __iter__(self):
        class KeyMapIter:
            def __iter__(self): return self
            def __init__(self, _map):
                self._map = _map
                self._keys = sorted(_map.keys())
            def next(self):
                if not self._keys: raise StopIteration()
                else:
                    k = self._keys.pop()
                    return (k, self._map[k])

        return KeyMapIter(self._map)

    def find_random_key_id(self):
        random.seed()
        while 1:
            # Initial partitioning. Rationale: totally arbitrary choice.
            nb = random.randint(1000000, 2**36-1)
            if not self._map.has_key(nb): return nb

class AdminConfig:
    """This class contains the global configuration of this program."""

    def __init__(self, config_path):
        self.teambox_ssl_cert_path = ""
        self.teambox_ssl_key_path = ""
        self.teambox_email_skey_path = ""
        self.teambox_license_skey_path = ""
        self.key_id_map_path = ""
        self.client_db_path = ""
        self.trusted_ca_path = ""
        self.bundle_path = ""
        self.unstable_bundle_path = ""
        self.enable_confirm = 0

        parser = ConfigParser.ConfigParser()
        parser.readfp(open(config_path))

        self.teambox_ssl_cert_path = parser.get("config", "teambox_ssl_cert_path")
        self.teambox_ssl_key_path = parser.get("config", "teambox_ssl_key_path")
        self.teambox_email_skey_path = parser.get("config", "teambox_email_skey_path")
        self.teambox_license_skey_path = parser.get("config", "teambox_license_skey_path")
        self.key_id_map_path = parser.get("config", "key_id_map_path")
        self.client_db_path = parser.get("config", "client_db_path")
        self.trusted_ca_path = parser.get("config", "trusted_ca_path")
        self.bundle_path = parser.get("config", "bundle_path")
        self.unstable_bundle_path = parser.get("config", "unstable_bundle_path")
        self.teambox_ca_config = parser.get("config", "teambox_ca_config")
        self.teambox_ca_cert_path = parser.get("config", "teambox_ca_cert_path")
        self.teambox_ca_key_path = parser.get("config", "teambox_ca_key_path")

        assert_file_exist(self.teambox_ca_config)
        assert_file_exist(self.teambox_ca_cert_path)
        assert_file_exist(self.teambox_ca_key_path)
        assert_file_exist(self.teambox_ssl_cert_path)
        assert_file_exist(self.teambox_ssl_key_path)
        assert_file_exist(self.teambox_email_skey_path)
        assert_file_exist(self.teambox_license_skey_path)
        assert_dir_exist(self.client_db_path)
        assert_dir_exist(self.trusted_ca_path)
        assert_file_exist(self.bundle_path)
        assert_file_exist(self.unstable_bundle_path)

        self.KeyMap = AdminKeyMap(self.key_id_map_path)

    # This function returns true if the specified key ID string is valid.
    def is_valid_key_id(self, key_id):
        try:
            nb = int(key_id)
            if nb <= 0 or nb > 2**63-1:
                raise Exception
        except Exception:
            return 0
        return 1

class ClientManager:
    """High level class to manager a set of client."""

    class ClientIterator:
        """Allows to iterator over all client currently stored in the database."""
        def next(self):
            m = None
            while len(self.file_list) > 0:
                m = self.file_list.pop()
                if os.path.isdir(os.path.join(self.mgr.admin_conf.client_db_path, m)):
                    break
                else:
                    m = None
            if not m:
                raise StopIteration()
            else:
                return self.mgr[m]
        def __iter__(self):
            return self
        def __init__(self, mgr):
            self.file_list = sorted(os.listdir(mgr.admin_conf.client_db_path))
            self.mgr = mgr

    def __init__(self, admin_conf):
        self.admin_conf = admin_conf
        self.client_cache = {}

    def __getitem__(self, kdn):
        if not kdn in self.client_cache:
            obj = ClientConfig(self.admin_conf, kdn)
            self.client_cache[kdn] = obj
        else:
            obj = self.client_cache[kdn]
        return obj

    def add(self, kdn):
        if kdn in self:
            raise Exception("Client %s already exists." % kdn)
        os.mkdir(os.path.join(self.admin_conf.client_db_path, kdn))
        self[kdn].write_config()
        return self[kdn]

    def __delitem__(self, kdn):
        if not kdn in self:
            raise Exception("Client %s does not exists." % kdn)
        shutil.rmtree(os.path.join(self.admin_conf.client_db_path, kdn), 0)

    def __contains__(self, kdn):
        """Return true if the client's directory exists."""
        return os.path.isdir(os.path.join(self.admin_conf.client_db_path, kdn))

    def __iter__(self):
        return self.ClientIterator(self)

class ClientCertManager:
    """Managed certificates signed for a client."""

    def __init__(self, client_conf):
        self.client_conf = client_conf
        self._cert_dir = os.path.join(self.client_conf.path, "cert")
        if not os.path.exists(self._cert_dir):
            os.mkdir(self._cert_dir)

    def sign(self, csr_data):
        """Sign a certificate, add it to the collection for the client."""
        csr = ssl.Req(req_data = csr_data)
        csr_client_path = GetUniquePath(self._cert_dir, "csr", ".pem")
        cert_client_path = csr_client_path.replace("csr", "cert")
        csr.save(csr_client_path)
        cmd = ["openssl", "ca",
               "-in", csr_client_path,
               "-out", cert_client_path,
               "-config", self.client_conf.admin_conf.teambox_ca_config,
               "-cert", self.client_conf.admin_conf.teambox_ca_cert_path,
               "-keyfile", self.client_conf.admin_conf.teambox_ca_key_path,
               "-notext",
               "-batch",
               "-days", "365"] # FIXME See if that can be configured in the CA config.
        get_cmd_output(cmd)
        return ssl.Cert(cert_file = cert_client_path)

class ClientKAPManager:
    """Manages a set of KAP generated for the client."""

    def __init__(self, client_conf):
        # Create the output directory if it doesn't exists.
        self.client_conf = client_conf
        self._kap_dir = os.path.join(self.client_conf.path, "kap")
        if not os.path.exists(self._kap_dir):
            os.mkdir(self._kap_dir)

    def get(self, kap_id):
        """Return store KAP data."""
        kf = os.path.join(self._kap_dir, kap_id) + ".tar.gz"
        if os.path.exists(kf):
            return KAP.read_KAP(kf)
        else:
            return None

    def exists(self, kap_id):
        """Return true of a KAP of such ID has been saved in the KAP manager."""
        kf = os.path.join(self._kap_dir, kap_id) + ".tar.gz"
        return os.path.exists(kf)

    def __iter__(self):
        class ClientKAPManagerIterator:
            def isfile(self, kap_file):
                return os.path.isfile(os.path.join(self._kap_dir, kap_file))
            def removeext(self, kap_file):
                return kap_file[0:kap_file.index(".")]
            def __iter__(self): return self
            def next(self):
                if not self._kap_files:
                    raise StopIteration()
                else:
                    return self._kap_files.pop()
            def __init__(self, kap_dir):
                self._kap_dir = kap_dir
                self._kap_files = map(self.removeext, filter(self.isfile, os.listdir(kap_dir)))
        return ClientKAPManagerIterator(self._kap_dir)

    def encrypt(self, kap_id, enc_kap_path, sig_key):
        """Encrypt a KAP for the client and signs it with a key."""
        kdata = self.get(kap_id)
        if not kdata:
            raise Exception("KAP %s doesn't exists" % kap_id)
        KAP.write_KAP(kdata, enc_kap_path,
                      do_encrypt = True,
                      teambox_email_skey = sig_key,
                      encrypt_pkey = self.client_conf.get_enc_pkey().key_path)

    def add(self, kdata):
        """Add a KAP to the client configuration."""
        # Get an unique name for the KAP file.
        s = time.strftime("%Y%m%d")
        kn = ""
        kp = ""
        d = 1
        while True:
            kn = "kap_%s_%s_%d" % (kdata.kap_type, s, d)
            kp = os.path.join(self._kap_dir, kn) + ".tar.gz"
            if not os.path.exists(kp):
                break
            else:
                d = d + 1
        # Write the raw KAP.
        KAP.write_KAP(kdata, kp, do_encrypt = False)
        return kn

# This class contains the configuration information of a client.
class ClientConfig:
    def __init__(self, admin_conf, kdn):
        self._save_config = False
        self.admin_conf = admin_conf

        # KDN.
        self.kdn = kdn

        # Path to the client directory, and the KAR and signature keys directories.
        self.path = self.admin_conf.client_db_path + "/" + kdn + "/"
        self._kar_dir = self.path + "kar/"
        self._sig_dir = self.path + "sig/"

        # Information written in the configuration file.
        self.kar_open = 0
        self.kar_verified = 0
        self.parent_kdn = None

        # Path to the keys of the client.
        self._sig_pkey_path = self.path + "sig/key.sig.pkey"
        self._sig_skey_path = self.path + "sig/key.sig.skey"
        self._enc_pkey_path = self.path + "kar/kar.enc.pkey"

        # Private informations, managed through __getattr__ hack
        # and/or instance methods.
        self._org_name = ""
        self._uses_apps = 0
        self._is_reseller = 0
        self._domain_set = set()

        self._lim_seats = None
        self._max_seats = None
        self._best_after = None
        self._best_before = None

        # Read the saved configuration for this client.
        self.read_config()
        self._save_config = True

        # KAP manager
        self.KapManager = ClientKAPManager(self)

        # Certificate manager
        self.CertManager = ClientCertManager(self)

        # Path to the client KOS package.
        self.kos_pkg_path = self.path + "client_kos.tar.gz"

    def get_sig_skey(self):
        """Return the private signature key or None."""
        if os.path.exists(self._sig_skey_path):
            return Key.fromFile(self._sig_skey_path)
        else:
            return None

    def set_sig_skey(self, kkey):
        """Set the private signature key for the client."""
        if not os.path.exists(self._sig_dir):
            os.mkdir(self._sig_dir)
        kkey.save(self._sig_skey_path)

    def get_sig_pkey(self):
        """Return the public signature key or None."""
        if os.path.exists(self._sig_pkey_path):
            return Key.fromFile(self._sig_pkey_path)
        else:
            return None

    def set_sig_pkey(self, kkey):
        """Set the public signature key for the client."""
        if not os.path.exists(self._sig_dir):
            os.mkdir(self._sig_dir)
        kkey.save(self._sig_pkey_path)

    def get_enc_pkey(self):
        """Return the public encryption key or None."""
        if os.path.exists(self._enc_pkey_path):
            return Key.fromFile(self._enc_pkey_path)
        else:
            return None

    def add_domain(self, domain_name):
        """Add a new domain in the list of domains for this company."""
        self._domain_set.add(domain_name)
        self.write_config()

    def del_domain(self, domain_name):
        """Remove a domain from the list of domains for this company."""
        self._domain_set.discard(domain_name)
        self.write_config()

    def rename(self, newkdn):
        """Change the KDN of a client."""
        os.rename(os.path.join(self.admin_conf.client_db_path, self.kdn),
                  os.path.join(self.admin_conf.client_db_path, newkdn))
        self.kdn = newkdn
        self.path = os.path.join(self.admin_conf.client_db_path, newkdn)
        self.write_config()

    def domains(self):
        """Return a list of the domains."""
        return list(self._domain_set.copy())

    def __getattr__(self, name):
        if "_%s" % name in self.__dict__:
            return self.__dict__["_%s" % name]
        else:
            if name in self.__dict__:
                return self.__dict__[name]
            else:
                raise AttributeError()

    def __setattr__(self, name, value):
        if name != '_save_config' and "_%s" % name in self.__dict__:
            self.__dict__["_%s" % name] = value
            if self.__dict__['_save_config']:
                self.write_config()
        else:
            self.__dict__[name] = value

    def has_sig_keys(self):
        return self.get_sig_pkey() and self.get_sig_skey()

    def kar_exists(self):
        """This function returns true if a KAR file is present."""
        return os.path.isfile(os.path.join(self.path + "kar/kar.bin"))

    def set_kar(self, kar_data):
        """Set the KAR for this client."""
        if os.path.exists(self._kar_dir):
            shutil.rmtree(self._kar_dir)
        os.mkdir(self._kar_dir)
        write_file(os.path.join(self._kar_dir, "kar.bin"), kar_data)

    def open_kar(self):
        if not self.kar_exists():
            raise Exception("No KAR file.")

        kar = self.get_kar_object()

        # Extract the KAR data inside the client directory.
        kar.cert.save(os.path.join(self.path, "kar/cert.pem"))
        kar.enc_pkey.save(os.path.join(self.path, "kar/kar.enc.pkey"))
        write_file(os.path.join(self.path, "kar/admin"), kar.admin)
        if kar.info:
            write_file(os.path.join(self.path, "kar/info"), kar.info)
        if kar.parent_kdn:
            write_file(os.path.join(self.path, "kar/parent_kdn"), kar.parent_kdn)

        return kar

    def email_key_exist(self):
        """This function returns true if the public encryption key and the signature
        key pair exist."""
        return self.get_sig_pkey() and self.get_sig_skey() and self.get_enc_pkey()

    def print_key_status(self):
        def _print_single_key_status(key_name, key):
            if key:
                print "%s %d, %s" % (key_name, int(key.id), key.owner)
            else:
                print "%s is not present" % (key_name)

        _print_single_key_status("Private signature key", self.get_sig_skey())
        _print_single_key_status("Public signature key", self.get_sig_pkey())
        _print_single_key_status("Public encryption key", self.get_enc_pkey())

    def check_key_consistency(self):
        """Check if the key for this client are consistent. This raises a KeyConsistency exception
        if the keys are not consistent."""
        last_key_id = None

        if not self.get_sig_skey():
            raise KeyConsistencyException("private signature key is not present")
        if not self.get_sig_pkey():
            raise KeyConsistencyException("public signature key is not present")
        if not self.get_enc_pkey():
            raise KeyConsistencyException("public encryption key is not present")

        all_keys = [self.get_sig_skey(), self.get_sig_pkey(), self.get_enc_pkey()]
        all_key_ids = map(lambda k: k.id, all_keys)
        key_id_ok = max(all_key_ids) == min(all_key_ids)

        owner_set = set()
        map(lambda k: owner_set.add(k.owner), all_keys)
        key_owner_ok = len(owner_set) == 1

        if not key_id_ok:
            raise KeyConsistencyException("the key IDs are not consistent")

        if not key_owner_ok:
            raise KeyConsistencyException("the key names are not consistent")

        return True

    def get_key_id(self):
        """This function returns the key ID contained in the public signature key."""
        if self.get_sig_pkey():
            return self.get_sig_pkey().id
        else:
            return None

    def get_kar_object(self):
        """This function returns the KAR data for this client."""
        return KAR.read_KAR(ssl.Key(key_file = self.admin_conf.teambox_ssl_key_path),
                            ssl.Cert(cert_file = self.admin_conf.teambox_ssl_cert_path),
                            self.path + "kar/kar.bin")

    def _gen_license_file(self, out):
        # Check that nothing is missing
        if not self.kdn: raise Exception("No KDN set.")
        if not self.lim_seats or not self.max_seats: raise Exception("Invalid seat count.")
        if not self.best_before or not self.best_after: raise Exception("Invalid license dates.")

        # Set a default parent KDN if there is none set.
        if not self.parent_kdn:
            pkdn = "none"
        else:
            pkdn = self.parent_kdn

        # Set the allowed license items.
        caps = ["sig", "enc", "pod"]
        if self.uses_apps:
            caps += ["apps"]

        # Generate the signed license.
        cmd = " ".join(["kctlbin",
                        "signlicense",
                        self.admin_conf.teambox_license_skey_path,
                        out,
                        self.kdn,
                        pkdn,
                        self.best_before,
                        self.best_after,
                        str(self.lim_seats),
                        str(self.max_seats),
                        str(self.is_reseller)] + caps)
        get_cmd_output(cmd, 1)

    def save_kap(self, kdata):
        """Save a KAP in the KAP manager."""
        kap_id = self.KapManager.add(kdata)
        return kap_id

    def encrypt_kap(self, kap_id, kap_out):
        """Encrypt a saved KAP."""
        self.KapManager.encrypt(kap_id, kap_out, self.admin_conf.teambox_email_skey_path)

    def new_license_kap(self):
        """Return a KAP object with just a license file."""
        lic_fd = None
        lic_path = None
        try:
            (lic_fd, lic_path) = tempfile.mkstemp()
            self._gen_license_file(lic_path)

            # Check that nothing is missing to generate the KAP.
            if not self.get_enc_pkey(): raise Exception("No public encryption key.")

            # Prepare the KAP data.
            kdata = KAP.KAPData()
            kdata.kap_type = "license"
            kdata.license = read_file(lic_path)
            kdata.email_enc_pkey = self.get_enc_pkey()

        finally:
            if lic_fd:
                os.close(lic_fd)
            if lic_path:
                os.unlink(lic_path)

        return kdata

    def new_kap(self, unstable_bundle = False):
        """This function returns a full KAP good to activate a client."""
        lic_fd = None
        lic_path = None
        kdata = None
        try:
            (lic_fd, lic_path) = tempfile.mkstemp()
            self._gen_license_file(lic_path)

            # Check that nothing is missing to generate the KAP.
            if not self.get_sig_pkey(): raise Exception("No public signature key.")
            if not self.get_sig_skey(): raise Exception("No private signature key.")
            if not self.get_enc_pkey(): raise Exception("No public encryption key.")
            if not self.get_key_id(): raise Exception("Failed to obtain key ID.")
            if not self.kdn: raise Exception("No KDN set.")

            # Prepare the KAP data.
            kdata = KAP.KAPData()
            kdata.kap_type = "activation"
            kdata.email_sig_pkey = self.get_sig_pkey()
            kdata.email_sig_skey = self.get_sig_skey()
            kdata.email_enc_pkey = self.get_enc_pkey()
            kdata.key_id = self.get_key_id()
            kdata.kdn = self.kdn
            kdata.license = read_file(lic_path)
            if unstable_bundle:
                kdata.bundle = read_file(self.admin_conf.unstable_bundle_path)
            else:
                kdata.bundle = read_file(self.admin_conf.bundle_path)

        finally:
            if lic_fd:
                os.close(lic_fd)
            if lic_path:
                os.unlink(lic_path)
        return kdata

    def new_upgrade_kap(self, unstable_bundle = False):
        """This functions returns a KAP with a tbxsosd bundle."""
        kdata = KAP.KAPData()
        kdata.kap_type = "upgrade"
        if unstable_bundle:
            kdata.bundle = read_file(self.admin_conf.unstable_bundle_path)
        else:
            kdata.bundle = read_file(self.admin_conf.bundle_path)
        return kdata

    # This function reads the configuration file of the client.
    def read_config(self):
        ini = os.path.join(self.path, "config.ini")
        if not os.path.exists(ini): return

        parser = ConfigParser.ConfigParser()
        parser.readfp(open(self.path + "config.ini"))
        self._org_name = parser.get("client", "org_name")
        self.kar_open = parser.getint("client", "kar_open")
        self.kar_verified = parser.getint("client", "kar_verified")

        if parser.has_option("client", "is_reseller"):
            self.is_reseller = parser.getint("client", "is_reseller")

        if parser.has_option("client", "best_after"):
            self.best_after = parser.get("client", "best_after")

        if parser.has_option("client", "best_before"):
            self.best_before = parser.get("client", "best_before")

        if parser.has_option("client", "lim_seats"):
            self.lim_seats = parser.getint("client", "lim_seats")

        if parser.has_option("client", "max_seats"):
            self.max_seats = parser.getint("client", "max_seats")

        if parser.has_option("client", "parent_kdn"):
            self.parent_kdn = parser.get("client", "parent_kdn")

        if parser.has_option("client", "uses_apps"):
            self.uses_apps = parser.get("client", "uses_apps")
        else:
            self.uses_apps = False

        domain_list = parser.items("domains")
        for pair in domain_list:
            if pair[0] != "@":
                self._domain_set.add(pair[0])

    # This function writes the configuration file of the current client. On
    # error, the current client is deselected if it was selected.
    def write_config(self):
        parser = ConfigParser.ConfigParser()

        parser.add_section("client")
        parser.set("client", "org_name", self._org_name)
        parser.set("client", "kar_open", self.kar_open)
        parser.set("client", "kar_verified", self.kar_verified)
        parser.set("client", "is_reseller", self.is_reseller)

        if self.parent_kdn:
            parser.set("client", "parent_kdn", self.parent_kdn)

        if self.best_after:
            parser.set("client", "best_after", self.best_after)

        if self.best_before:
            parser.set("client", "best_before", self.best_before)

        if self.lim_seats:
            parser.set("client", "lim_seats", self.lim_seats)

        if self.max_seats:
            parser.set("client", "max_seats", self.max_seats)

        # Save the organization name in the keys.
        for k in [self.get_sig_pkey(), self.get_sig_skey(), self.get_enc_pkey()]:
            if k: k.setkeyname(self._org_name)

        parser.set("client", "uses_apps", self.uses_apps)

        parser.add_section("domains")
        if self._domain_set:
            for domain in self._domain_set:
                parser.set("domains", domain, domain)
        else:
            parser.set("domains", "@", "@")

        f = open(self.path + "config.ini", "wb")
        parser.write(f)
        f.close()
