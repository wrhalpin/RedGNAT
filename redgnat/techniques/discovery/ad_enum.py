"""
Active Directory Enumeration — T1087.002, T1069.002, T1482

Read-only LDAP enumeration of Active Directory. Discovers users, groups,
OUs, domain trusts, and Group Policy Objects.

Emulation only: uses read-only service account credentials; never modifies AD.

External dependency: ldap3 (pip install ldap3).
"""
from __future__ import annotations

import logging
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext

logger = logging.getLogger(__name__)

# LDAP search filters
_USER_FILTER = "(&(objectClass=user)(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
_GROUP_FILTER = "(&(objectClass=group))"
_TRUST_FILTER = "(objectClass=trustedDomain)"
_GPO_FILTER = "(objectClass=groupPolicyContainer)"
_ADMIN_GROUP_FILTER = "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)(cn=Administrators)))"

# Attributes to retrieve per object type
_USER_ATTRS = [
    "sAMAccountName", "userPrincipalName", "displayName", "mail",
    "memberOf", "lastLogonTimestamp", "userAccountControl",
    "pwdLastSet", "whenCreated",
]
_GROUP_ATTRS = ["cn", "description", "member", "memberOf", "groupType"]
_TRUST_ATTRS = ["name", "trustDirection", "trustType", "trustAttributes", "flatName"]
_GPO_ATTRS = ["cn", "displayName", "gPCFileSysPath", "versionNumber"]


class ADEnumTechnique(Technique):
    """
    ATT&CK T1087.002 / T1069.002 / T1482 — Active Directory Enumeration.

    Performs read-only LDAP queries to enumerate:
    - Domain users (enabled accounts)
    - Security groups and memberships
    - Privileged group members (Domain Admins, Enterprise Admins, etc.)
    - Domain trusts
    - Group Policy Objects

    Parameters (ctx.params)
    -----------------------
    ldap_server : str
        Override config ldap.server.
    base_dn : str
        Override config ldap.base_dn.
    bind_dn : str
        Override config ldap.bind_dn.
    bind_password : str
        Override config ldap.bind_password.
    max_users : int
        Maximum number of user records to return (default 500).
    """

    technique_id = "T1087.002"
    tactic = "discovery"
    name = "Active Directory Account & Group Discovery"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                "Would enumerate AD users, groups, trusts, and GPOs via LDAP",
            )

        try:
            import ldap3  # type: ignore[import]
        except ImportError:
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[],
                error="ldap3 not installed — pip install ldap3",
            )

        from redgnat.config import RedGNATConfig

        cfg = RedGNATConfig()
        server_addr = ctx.params.get("ldap_server", cfg.ldap_server)
        base_dn = ctx.params.get("base_dn", cfg.ldap_base_dn)
        bind_dn = ctx.params.get("bind_dn", cfg.ldap_bind_dn)
        bind_pw = ctx.params.get("bind_password", cfg.ldap_bind_password)
        max_users = int(ctx.params.get("max_users", 500))

        if not server_addr or not base_dn:
            return self._blocked_result(ctx, "ldap.server or ldap.base_dn not configured")

        try:
            server = ldap3.Server(
                server_addr,
                port=cfg.ldap_port,
                use_ssl=cfg.ldap_use_ssl,
                get_info=ldap3.ALL,
                connect_timeout=10,
            )
            conn = ldap3.Connection(
                server,
                user=bind_dn,
                password=bind_pw,
                authentication=ldap3.SIMPLE,
                read_only=True,  # never write
                auto_bind=True,
            )
        except Exception as exc:
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[],
                error=f"LDAP connection failed: {exc}",
            )

        findings: list[dict] = []
        evidence: list[dict] = []

        try:
            # 1. Users
            users = self._search(conn, base_dn, _USER_FILTER, _USER_ATTRS, max_users)
            findings.append({"category": "users", "count": len(users), "sample": users[:10]})
            evidence.append({"category": "users", "records": users})
            logger.info("ADEnum: found %d enabled user accounts [run=%s]", len(users), ctx.run_id)

            # 2. All groups
            groups = self._search(conn, base_dn, _GROUP_FILTER, _GROUP_ATTRS, 500)
            findings.append({"category": "groups", "count": len(groups), "sample": groups[:10]})

            # 3. Privileged group members
            priv_groups = self._search(
                conn, base_dn, _ADMIN_GROUP_FILTER, _GROUP_ATTRS, 20
            )
            findings.append(
                {
                    "category": "privileged_groups",
                    "count": len(priv_groups),
                    "groups": priv_groups,
                }
            )
            logger.info(
                "ADEnum: found %d privileged groups [run=%s]", len(priv_groups), ctx.run_id
            )

            # 4. Domain trusts
            trusts = self._search(conn, base_dn, _TRUST_FILTER, _TRUST_ATTRS, 50)
            findings.append({"category": "trusts", "count": len(trusts), "trusts": trusts})

            # 5. GPOs
            gpos = self._search(conn, base_dn, _GPO_FILTER, _GPO_ATTRS, 100)
            findings.append({"category": "gpos", "count": len(gpos)})

        except Exception as exc:
            logger.warning("ADEnum query failed: %s", exc)
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=findings,
                evidence=evidence,
                error=str(exc),
            )
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return self._make_result(ctx, ResultStatus.SUCCESS, findings, evidence)

    @staticmethod
    def _search(
        conn: Any, base_dn: str, search_filter: str, attributes: list[str], limit: int
    ) -> list[dict]:
        import ldap3

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            size_limit=limit,
        )
        results = []
        for entry in conn.entries:
            record: dict[str, Any] = {}
            for attr in attributes:
                val = getattr(entry, attr, None)
                if val is not None:
                    try:
                        record[attr] = val.value
                    except Exception:
                        record[attr] = str(val)
            results.append(record)
        return results
