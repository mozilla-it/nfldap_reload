# --- do not commit ---
LDAP_URL='ldap://<%= scope.lookupvar('::ldapvip') %>'
LDAP_BIND_DN='<%= scope.function_hiera(['secrets_netfilter_ssh_bind_username']) %>'
LDAP_BIND_PASSWD='<%= scope.function_hiera(['secrets_netfilter_ssh_bind_password']) %>'
# --- end of do not commit ---
