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

import os, sys, string, datetime
from datetime import datetime, timedelta

class KActToolsException(Exception):
    pass

# This function prompts the user for a confirmation (y/n). It returns true if
# the confirmation was given. Note: I wrote this on a friday evening.
def get_confirm(prompt, assume_answer = None):
    try:
        attempt = 0

        while 1:
            if not assume_answer:
                res = raw_input(prompt + " ")
                res = string.lower(res)
            else:
                res = assume_answer

            if (res == "yes" or res == "aye" or res == "sure" or res == "of course" or\
                res == "go ahead" or res == "why not" or res == "yeah" or res == "y"): return 1
            if (res == "no" or res == "nay" or res == "nah" or res == "never" or res == "n"): return 0

            attempt += 1
            if attempt > 1: sys.stdout.write("You stupid mammal. ")
            print "Please answer with 'y' or 'n'.\n"

    except Exception:
        print ""
        raise KeyboardInterrupt

# This function prompts the user for a string. It returns the string entered,
# which can be "".
def wizard_prompt(prompt, default_value = None):
    try:
        if default_value:
            s = raw_input(prompt + (" (%s) " % default_value))
        else:
            s = raw_input(prompt + " ")

        if default_value and s == "":
            s = default_value

        return s

    except Exception:
        print ""
        raise KeyboardInterrupt

# This function is used to abort the wizard when a command fail.
def wizard_exec(intr, cmd_name, *params):
    if ret_code: raise KeyboardInterrupt

# This function returns the path to the directory of the client having the KDN
# specified. The path will end with a '/'.
def kdn_client_path(intr, kdn):
    return intr.admin_conf.client_db_path + "/" + kdn + "/"

# This function returns true if a client having the specified KDN exists.
def client_exist(intr, kdn):
    return os.path.isdir(kdn_client_path(intr, kdn))

def input_license_info(intr):
    if get_confirm("Is the client a service reseller?"):
        intr.run_command(["setreseller", "on"])
    else:
        intr.run_command(["setreseller", "off"])

    print ""
    lim_seats = None
    while not lim_seats:
        try:
            lim_seats = int(wizard_prompt("Soft seat count limit (-1 for no limit): "))
        except Exception, e:
            if intr.debug: raise e
            else: pass

    max_seats = None
    while not max_seats:
        try:
            max_seats = int(wizard_prompt("Hard seat count limit (-1 for no limit): "))
        except Exception, e:
            if intr.debug: raise e
            else: pass

    print ""

    now = datetime.utcnow()
    now_next_year = datetime(year = now.year + 1, month = now.month, day = now.day)

    intr.run_command(["setseats", str(lim_seats), str(max_seats)])

    today = now.strftime("%Y-%m-%d")
    today_next_year = now_next_year.strftime("%Y-%m-%d")

    # Best before date.
    s = "Input the date at which the license is valid by:"
    best_after = wizard_prompt(s, today)

    # Best after date.
    s = "Input the date at which the license will expire:"
    best_before = wizard_prompt(s, today_next_year)

    intr.run_command(["setdates", best_after, best_before])

    print ""

    # License capacities
    if get_confirm("Is the client allowed to use applications?"):
        intr.run_command(["setapps", "on"])
    else:
        intr.run_command(["setapps", "off"])
