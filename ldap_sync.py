#!/usr/bin/env python3
import os
import ldap
import logging
from yaml import safe_load
from airflow.www_rbac.app import cached_appbuilder

logger = logging.getLogger(__name__)
f_handler = logging.FileHandler('/var/log/airflow_ldap_sync.log')
f_format = logging.Formatter('%(asctime)s - %(message)s')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)
logger.info('Starting airflow ldap sync')

ldap_sync_conf_file = os.path.join(os.environ['AIRFLOW_HOME'], 'ldap_sync.yaml')
with open(ldap_sync_conf_file) as f:
    ldap_sync_config = safe_load(f)

appbuilder = cached_appbuilder()
con = ldap.initialize(appbuilder.sm.auth_ldap_server)
con.set_option(ldap.OPT_REFERRALS, 0)
appbuilder.sm._bind_indirect_user(ldap, con)


for group in ldap_sync_config['group_role_map']:
    filter_str = \
                "(&(ObjectClass=%s)(%s=%s))" % (
                    ldap_sync_config['group_object_class'],
                    ldap_sync_config['group_name_attr'],
                    group
                )
    group_cn = con.search_s(
            appbuilder.sm.auth_ldap_search,
            ldap.SCOPE_SUBTREE,
            filter_str,
            [
                ldap_sync_config['group_name_attr']
            ]
        )[0][0]
    filter_str = \
                "(&(ObjectClass=%s)(%s=%s))" % (
                    ldap_sync_config['user_object_class'],
                    ldap_sync_config['user_group_name_attr'],
                    group_cn
                )
    users = con.search_s(
            appbuilder.sm.auth_ldap_search,
            ldap.SCOPE_SUBTREE,
            filter_str,
            [
                appbuilder.sm.auth_ldap_uid_field
            ]
        )
    user_list = [sam_account_name.get(appbuilder.sm.auth_ldap_uid_field)[0].decode('utf-8') for sam_account_name in [user[1] for user in users]]

    # Adding new users:
    for username in user_list:
        user = appbuilder.sm.find_user(username)
        if not user:
            new_user = appbuilder.sm._search_ldap(ldap, con, username)
            ldap_user_info = new_user[0][1]
            if new_user:
                user = appbuilder.sm.add_user(
                    username=username,
                    first_name=appbuilder.sm.ldap_extract(
                        ldap_user_info,
                        appbuilder.sm.auth_ldap_firstname_field,
                        username
                    ),
                    last_name=appbuilder.sm.ldap_extract(
                        ldap_user_info,
                        appbuilder.sm.auth_ldap_lastname_field,
                        username
                    ),
                    email=appbuilder.sm.ldap_extract(
                        ldap_user_info,
                        appbuilder.sm.auth_ldap_email_field,
                        username + '@email.notfound'
                    ),
                    role=appbuilder.sm.find_role(ldap_sync_config['group_role_map'].get(group))
                )
                if user:
                    logger.info('User {} created'.format(user.username))
            else:
                logger.info('AD user {} not found'.format(username))


ab_user_list = appbuilder.sm.get_all_users()
for user in ab_user_list:
    if appbuilder.sm._search_ldap(ldap, con, user.username):
        # Mapping additional roles:
        filter_str = \
                    "(&(ObjectClass=%s)(%s=%s))" % (
                        ldap_sync_config['user_object_class'],
                        appbuilder.sm.auth_ldap_uid_field,
                        user.username
                    )
        user_cn = con.search_s(
                appbuilder.sm.auth_ldap_search,
                ldap.SCOPE_SUBTREE,
                filter_str,
                [
                    appbuilder.sm.auth_ldap_uid_field
                ]
            )[0][0]
        filter_str = \
                    "(&(ObjectClass=%s)(%s=%s)%s)" % (
                        ldap_sync_config['group_object_class'],
                        ldap_sync_config['group_member_attr'],
                        user_cn,
                        ldap_sync_config['group_search_filter']
                    )
        groups = con.search_s(
                appbuilder.sm.auth_ldap_search,
                ldap.SCOPE_SUBTREE,
                filter_str,
                [
                    ldap_sync_config['group_name_attr']
                ]
            )
        group_list = [cn.get(ldap_sync_config['group_name_attr'])[0].decode('utf-8') for cn in [group[1] for group in groups]]
        synced_roles = []
        for group in group_list:
            role = appbuilder.sm.find_role(ldap_sync_config['group_role_map'].get(group))
            if role:
                synced_roles.append(role)
        if sorted(user.roles, key = lambda x: x.name) != sorted(synced_roles, key = lambda x: x.name):
            user.roles = synced_roles
            appbuilder.sm.update_user(user)
            logger.info('Roles for user {} updated: {}'.format(user.username, user.roles))

    else:
        # Deleting fired users:
        username = user.username
        if appbuilder.sm.del_register_user(user):
            logger.info('User {} deleted.'.format(username))

logger.info('Finished airflow ldap sync')
logger.info('')
