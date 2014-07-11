# --- do not commit ---
LDAP_URL='ldap://<%= scope.lookupvar('::ldapvip') %>'
LDAP_BIND_DN='<%= scope.function_hiera(['secrets_netfilter_ssh_bind_username']) %>'
LDAP_BIND_PASSWD='<%= scope.function_hiera(['secrets_netfilter_ssh_bind_password']) %>'
# --- end of do not commit ---

MOZDEF_URL=''
# Will also log to syslog, not just MozDef
USE_SYSLOG=True
# Will only log to syslog, in case MozDef is not supported, if set to false (not recommended)
USE_MOZDEF=True
