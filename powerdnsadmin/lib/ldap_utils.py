from re import search
import traceback
from collections import OrderedDict

import ldap

from flask import current_app as app

from ..models import Setting

LDAP_TYPE = Setting().get("ldap_type")
LDAP_URI = Setting().get("ldap_uri")
LDAP_BASE_DN = Setting().get("ldap_base_dn")
LDAP_DOMAIN = Setting().get("ldap_domain")
LDAP_ADMIN_USERNAME = Setting().get("ldap_admin_username")
LDAP_ADMIN_PASSWORD = Setting().get("ldap_admin_password")
LDAP_FILTER_BASIC = Setting().get("ldap_filter_basic")
LDAP_FILTER_USERNAME = Setting().get("ldap_filter_username")
LDAP_FILTER_GROUP = Setting().get("ldap_filter_group")
LDAP_FILTER_GROUPNAME = Setting().get("ldap_filter_groupname")
LDAP_ADMIN_GROUP = Setting().get("ldap_admin_group")
LDAP_OPERATOR_GROUP = Setting().get("ldap_operator_group")
LDAP_USER_GROUP = Setting().get("ldap_user_group")
LDAP_GROUP_SECURITY_ENABLED = Setting().get("ldap_sg_enabled")

LDAP_VALID_TYPES = ["ldap", "ad"]
LDAP_USER_ATTRIBUTES = OrderedDict(
    email="mail",
    lastname="sn",
    firstname="givenName",
)
LDAP_GROUP_SECURITY_ROLES = OrderedDict(
    Administrator=LDAP_ADMIN_GROUP,
    Operator=LDAP_OPERATOR_GROUP,
    User=LDAP_USER_GROUP,
)


def ldap_init_conn():
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn = ldap.initialize(LDAP_URI)

    conn.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
    conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    conn.set_option(ldap.OPT_TIMEOUT, 15)
    conn.protocol_version = ldap.VERSION3

    return conn


def is_ldap_user(username, password):
    """
    Valid LDAP user authentication then disconnect
    """
    user_binded = False
    ldap_username = username

    if LDAP_TYPE == "ad":
        ldap_username = f"{username}@{LDAP_DOMAIN}"

    try:
        conn = ldap_init_conn()
        conn.simple_bind_s(ldap_username, password)
        user_binded = True

        # Disconnect and close connection
        conn.unbind_s()

    except ldap.LDAPError as e:
        app.logger.error(e)

    return user_binded


def ldap_auth(conn, username, password):
    """
    Authenticate to LDAP with :
    - User credentials when LDAP AD
    - Admin credentials for others LDAP
    """
    ldap_username = LDAP_ADMIN_USERNAME
    ldap_password = LDAP_ADMIN_PASSWORD

    if LDAP_TYPE == "ad":
        ldap_username = f"{username}@{LDAP_DOMAIN}"
        ldap_password = password

    try:
        conn.simple_bind_s(ldap_username, ldap_password)
    except ldap.LDAPError as e:
        app.logger.error(e)


def ldap_search(conn, search_filter, base_dn):
    results = []

    try:
        results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)
    except ldap.LDAPError as e:
        app.logger.error(e)
        app.logger.debug(f"base_dn={base_dn}")
        app.logger.debug(traceback.format_exc())

    return results


def ldap_get_user(conn, username):
    user = None

    ldap_result = ldap_search(
        conn, f"({LDAP_FILTER_USERNAME}={username})", LDAP_BASE_DN
    )

    if not ldap_result:
        return user

    dn = ldap_result[0][0]
    userAttributes = ldap_result[0][1]
    user = {
        "username": username,
        "role": "User",
        "dn": dn,
    }

    for field, ldap_attribute in LDAP_USER_ATTRIBUTES.items():
        try:
            user[field] = userAttributes[ldap_attribute][0].decode("utf-8")
        except Exception as e:
            user[field] = ""
            app.logger.warning(
                f"LDAP Reading user '{username}' attribute '{ldap_attribute}'"
            )
            app.logger.debug(traceback.format_exc())

    return user


def ldap_get_user_role(conn, username):
    """
    Filter LDAP Security groups where user is member
    Return application role name, empty string if no role
    """
    role_name = ""
    group_search_filter = (
        f"(&({LDAP_FILTER_GROUPNAME}={username}){LDAP_FILTER_GROUP})"
    )
    app.logger.debug(f"Ldap groupSearchFilter {group_search_filter}")

    for role, ldap_group in LDAP_GROUP_SECURITY_ROLES.items():
        if not ldap_group or not ldap_search(group_search_filter, ldap_group):
            continue

        role_name = role
        app.logger.debug(f"User '{username}' is part of {ldap_group} group")
        app.logger.info(
            f"Access granted for user '{username}' with role '{role_name}'"
        )

        # Exit loop on first found
        break

    return role_name


def ldap_ad_get_user_role(conn, username, user_dn):
    """
    Filter LDAP Security groups where user is nested member
    Return application role name, empty string if no role
    """
    role_name = ""
    search_groups = ""

    for ldap_group in LDAP_GROUP_SECURITY_ROLES.values():
        if not ldap_group:
            continue

        search_groups += f"(distinguishedName={ldap_group})"

    search_group_member = f"(member:1.2.840.113556.1.4.1941:={user_dn})"
    search_filter = f"(&(|{search_groups}){search_group_member})"
    app.logger.debug(f"Ldap groupSearchFilter {search_filter}")

    user_groups = [
        group[0] for group in ldap_search(conn, search_filter, LDAP_BASE_DN)
    ]

    if not user_groups:
        app.logger.error(
            f"Access deny for user '{username}', reason: "
            "User not member of security groups"
        )
        return role_name

    app.logger.debug(
        f"LDAP User security groups for user '{username}': "
        " ".join(user_groups)
    )

    for role, ldap_group in LDAP_GROUP_SECURITY_ROLES.items():
        if not ldap_group or not ldap_group in user_groups:
            continue

        role_name = role
        app.logger.info(
            f"Access granted for user '{username}' with role '{role_name}'"
        )

        # Exit loop on first found
        break

    return role_name


def get_user(username, password, src_ip="", trust_user=False):
    """
    Get user detail from ldap and do:
    - User authentication through ldap if not trusted
    - User information search
    - User group validation when security group are enabled

    """
    if LDAP_TYPE not in LDAP_VALID_TYPES:
        app.logger.error(f"LDAP type '{LDAP_TYPE}' not supported")
        return None

    # Return empty user when testing user / password of untrusted user
    if not trust_user and not is_ldap_user(username, password):
        app.logger.error(
            f"User '{username}' input a wrong LDAP password. "
            f"Authentication request from {src_ip}"
        )
        return None

    conn = ldap_init_conn()

    # bind ldap connection
    ldap_auth(conn, username, password)

    # Get data about user
    user = ldap_get_user(conn, username)

    if not user:
        app.logger.warning(
            f"LDAP User '{username}' does not exist. "
            f"Authentication request from {src_ip}"
        )
        return None

    if user and LDAP_GROUP_SECURITY_ENABLED:
        if LDAP_TYPE == "ad":
            user["role"] = ldap_ad_get_user_role(conn, username, user.get("dn"))
        elif LDAP_TYPE == "ldap":
            user["role"] = ldap_get_user_role(conn, username)

    # Disconnect and close connection
    conn.unbind_s()

    return user
