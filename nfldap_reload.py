#!/usr/bin/env python
# vim: set noexpandtab:ts=8
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
# jdow@mozilla.com
# jvehent@mozilla.com
# bhourigan@mozilla.com
# gdestuynder@mozilla.com
#
# Requires:
# libnfldap

import libnfldap
import os
import pwd
import sys
import syslog
from tempfile import mkstemp
import time
import imp

cfg_path = ['nfldap_reload.conf', '/etc/nfldap_reload.conf']
config = None

for cfg in cfg_path:
	if os.path.isfile(cfg):
		try:
			config = imp.load_source('config', cfg)
		except:
			pass

if config == None:
	print("Failed to load config")
	sys.exit(1)

def log(msg):
	""" Send a message to syslog """
	syslog.openlog('nfldap_reload', 0, syslog.LOG_DAEMON)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

# This script generates a tree of rules that efficiently looks up packets
# belonging to a given user. The tree is composed of one chain for each
# VPN group. Then each user has a custom chain that point to the
# proper VPN chains based on the user's group membership.
#
# --- PSEUDO CODE
# For each VPN group:
#   create iptables chain `vpngroupname`
#   for each iphostnumber in vpn group:
#	   insert iptables rule in chain `vpngroupname`
#
# For each local user:
#   create iptables chain `username`
#   insert jump rule from OUTPUT & FORWARD to chain `username`
#   obtain list of vpn groups user belong to
#   for each vpn group:
#	   create jump rule from user chain to `vpngroupname` chain
#   append DROP rule to user chain
#
def main():
	ipt = libnfldap.IPTables()
	ldap = libnfldap.LDAP(config.LDAP_URL, config.LDAP_BIND_DN, config.LDAP_BIND_PASSWD)
	ipset = libnfldap.IPset()

	gen_start_time = time.time()

	# find all vpn groups and create chains
	acls = ldap.getACLs('ou=groups,dc=mozilla',"(cn=vpn_*)")
	for group,dests in acls.iteritems():
		ipt.newFilterChain(group)
		for dest,desc in dests.iteritems():
			if libnfldap.is_cidr(dest):
				ipt.acceptIP(group, dest, desc)
			else:
				ip = dest.split(":", 1)[0]
				ports = dest.split(":", 1)[1]
				if len(ports) > 0:
					ipt.acceptIPPortProto(group, ip, ports, "tcp", desc)
					ipt.acceptIPPortProto(group, ip, ports, "udp", desc)
				else:
					ipt.acceptIP(group, ip, desc)

	# get a list of all LDAP users
	query = '(&(objectClass=mozComPerson)(objectClass=posixAccount))'
	res = ldap.query('dc=mozilla', query, ['uid', 'uidNumber'])
	users = {}

	# get users from the system, the find the corresponding ldap record
	for p in pwd.getpwall():
		if p.pw_uid > 500:
			# iterate over the ldap records
			for dn, attr in res:
				uid = attr['uid'][0]
				uidNumber = attr['uidNumber'][0]
				if uidNumber == str(p.pw_uid) and uid == p.pw_name:
					# store the user
					users[uidNumber] = {'dn': dn, 'uid': uid}

	## iterate over the users and create the rules
	for uidNumber,attr in users.iteritems():
		dn = attr['dn']
		uid = attr['uid']
		# create a custom chain for the user
		ipt.newFilterChain(uid)
		# add rules to forward this user's packets to the custom chain
		r = "-A OUTPUT -m owner --uid-owner " +  uidNumber + " -m state --state NEW -j " + uid
		ipt.appendFilterRule(r)

		# find groups memberships of the user
		acls = ldap.getACLs('ou=groups,dc=mozilla',
							"(&(member="+dn+")(cn=vpn_*))")

		# iterate through the ACLs and send the user to the group chains
		for group,dests in acls.iteritems():
			ipt.appendFilterRule("-A " + uid + " -j " + group)

		# add a DROP at the end of the user rules
		ipt.appendFilterRule("-A " + uid + " -j DROP")

	# set a default drop policy at the end of the ruleset
	ipt.insertSaneDefaults()
	#ipt.appendDefaultDrop()

	# template and print the iptables rules
	tmpfd, tmppath = mkstemp()
	f = open(tmppath, 'w')
	f.write(ipt.template())
	f.close()
	os.close(tmpfd)

	gen_time = time.time() - gen_start_time
	load_start_time = time.time()
	# run iptables-restore
	command = "/sbin/iptables-restore %s" % (tmppath)
	status = os.system(command)
	load_time = time.time() - load_start_time
	if status == -1:
		log("ERROR: failed to load iptables rules from '%s'. generation time=%s seconds, loading time=%s seconds" % (tmppath, gen_time, load_time))

	log("iptables rules reloaded successfully. generation time=%s seconds, loading time=%s seconds" % (gen_time, load_time))

if __name__ == "__main__":
	main()
