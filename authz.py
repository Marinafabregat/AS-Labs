"""
PEP, PIP and AuthzForce PDP client (XACML 3.0).

Single access-decision point for the application:
- PAP: builds the XACML 3.0 PolicySet and publishes a new version to AuthzForce
       at startup, then points the PDP root policy expression to it.
- PIP: converts SQLModel objects into attributes (*_attrs helpers).
- PDP: every decision is requested from AuthzForce as an XACML 3.0 XML request.
       Only Permit grants access.
- PEP: can() filters lists, enforce() protects actions.

Routes must not compare roles or account states directly.
"""
import logging
import os
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Optional
from urllib.parse import urljoin

import httpx
from fastapi import HTTPException

from models import Item, ItemReport, User, UserReport


log = logging.getLogger("authz")
audit = logging.getLogger("audit")

AUTHZFORCE_BASE_URL = os.getenv(
    "AUTHZFORCE_BASE_URL",
    "http://localhost:8080/authzforce-ce",
)
AUTHZFORCE_URL: Optional[str] = None

XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
AUTHZ_REST_NS = "http://authzforce.github.io/rest-api-model/xmlns/authz/5"
XACML_FUNC = "urn:oasis:names:tc:xacml:1.0:function:"
XACML_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
XACML_RESOURCE = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
XACML_ACTION = "urn:oasis:names:tc:xacml:3.0:attribute-category:action"
XSD_STRING = "http://www.w3.org/2001/XMLSchema#string"

POLICY_SET_ID = "marketplace-policyset"

POLICY_COMBINING = (
    "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides"
)
RULE_COMBINING = (
    "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"
)

ET.register_namespace("", XACML_NS)
ET.register_namespace("authz", AUTHZ_REST_NS)

Builder = Callable[[ET.Element], None]


# ============================================================
# XML builders (PAP)
# ============================================================

def _tag(name: str) -> str:
    return f"{{{XACML_NS}}}{name}"


def _el(parent, name: str, attrs: Optional[dict] = None):
    return ET.SubElement(parent, _tag(name), attrs or {})


def _one(attr_id: str, category: str) -> Builder:
    """string-one-and-only over an attribute (fails closed if it is missing)."""
    def build(parent):
        apply = _el(parent, "Apply", {"FunctionId": XACML_FUNC + "string-one-and-only"})
        _el(apply, "AttributeDesignator", {
            "AttributeId": attr_id,
            "Category": category,
            "DataType": XSD_STRING,
            "MustBePresent": "true",
        })
    return build


def _lit(value: Any) -> Builder:
    """String literal."""
    def build(parent):
        _el(parent, "AttributeValue", {"DataType": XSD_STRING}).text = str(value)
    return build


def _fn(name: str, *args: Builder) -> Builder:
    """Generic XACML function application."""
    def build(parent):
        apply = _el(parent, "Apply", {"FunctionId": XACML_FUNC + name})
        for arg in args:
            arg(apply)
    return build


def _eq(attr_id: str, category: str, value: Any) -> Builder:
    """Attribute equals a literal value."""
    return _fn("string-equal", _one(attr_id, category), _lit(value))


def _eq_attrs(attr_a: str, cat_a: str, attr_b: str, cat_b: str) -> Builder:
    """Two attributes have the same value."""
    return _fn("string-equal", _one(attr_a, cat_a), _one(attr_b, cat_b))


def _any(*args: Builder) -> Builder:
    """Logical OR."""
    return _fn("or", *args)


def _all(*args: Builder) -> Builder:
    """Logical AND."""
    return _fn("and", *args)


def _not(arg: Builder) -> Builder:
    """Logical NOT."""
    return _fn("not", arg)


def _target(parent, matches: list[tuple[str, str, Any]]):
    """
    Every (attribute, category, value) tuple must match.
    An empty list produces an empty Target, which matches everything.
    """
    target = _el(parent, "Target")
    if matches:
        all_of = _el(_el(target, "AnyOf"), "AllOf")
        for attr_id, category, value in matches:
            match = _el(all_of, "Match", {"MatchId": XACML_FUNC + "string-equal"})
            _el(match, "AttributeValue", {"DataType": XSD_STRING}).text = str(value)
            _el(match, "AttributeDesignator", {
                "AttributeId": attr_id,
                "Category": category,
                "DataType": XSD_STRING,
                "MustBePresent": "true",
            })
    return target


def _policy(root, policy_id: str, resource_type: Optional[str]):
    """resource_type=None creates a Policy without a Target (applies to every resource)."""
    policy = _el(root, "Policy", {
        "PolicyId": policy_id,
        "Version": "1.0",
        "RuleCombiningAlgId": RULE_COMBINING,
    })
    matches = [("resource-type", XACML_RESOURCE, resource_type)] if resource_type else []
    _target(policy, matches)
    return policy


def _rule(policy, rule_id: str, effect: str, *,
          action: Optional[str] = None,
          role: Optional[str] = None,
          when: Optional[Builder] = None):
    """Creates a Rule with an optional action/role target and an optional condition."""
    rule = _el(policy, "Rule", {"RuleId": rule_id, "Effect": effect})
    matches = []
    if action is not None:
        matches.append(("action-id", XACML_ACTION, action))
    if role is not None:
        matches.append(("role", XACML_SUBJECT, role))
    _target(rule, matches)
    if when is not None:
        when(_el(rule, "Condition"))
    return rule


# Reusable predicates. Each one produces exactly one XACML expression.

def _authenticated(expected: bool = True) -> Builder:
    return _eq("authenticated", XACML_SUBJECT, "true" if expected else "false")


def _owner() -> Builder:
    """The subject is the owner of the resource."""
    return _eq_attrs("subject-id", XACML_SUBJECT, "owner_id", XACML_RESOURCE)


def _reporter() -> Builder:
    """The subject is the author of the report."""
    return _eq_attrs("subject-id", XACML_SUBJECT, "reporter_id", XACML_RESOURCE)


def _is_staff() -> Builder:
    return _any(
        _eq("role", XACML_SUBJECT, "admin"),
        _eq("role", XACML_SUBJECT, "moderator"),
    )


def _subject_suspended() -> Builder:
    return _any(
        _eq("is_banned", XACML_SUBJECT, "true"),
        _eq("is_blacklisted", XACML_SUBJECT, "true"),
    )


def _resource_suspended() -> Builder:
    return _any(
        _eq("is_banned", XACML_RESOURCE, "true"),
        _eq("is_blacklisted", XACML_RESOURCE, "true"),
    )


def _hidden_item() -> Builder:
    return _eq("is_blacklisted", XACML_RESOURCE, "true")


def _target_is_staff() -> Builder:
    return _any(
        _eq("target_role", XACML_RESOURCE, "admin"),
        _eq("target_role", XACML_RESOURCE, "moderator"),
    )


def _status_is(*values: str) -> Builder:
    return _any(*[_eq("status", XACML_RESOURCE, v) for v in values])


# ============================================================
# PolicySet (PAP)
# ============================================================

def _build_policy_set(version: str) -> str:
    root = ET.Element(_tag("PolicySet"), {
        "PolicySetId": POLICY_SET_ID,
        "Version": version,
        "PolicyCombiningAlgId": POLICY_COMBINING,
    })
    _el(root, "Target")

    # 1. Suspended or banned accounts: read-only access to public content.
    account_status = _policy(root, "account-status-policy", None)
    _rule(
        account_status,
        "deny-suspended-account-except-read",
        "Deny",
        when=_all(
            _subject_suspended(),
            _not(_eq("action-id", XACML_ACTION, "read")),
        ),
    )

    # 2. Session: an authenticated account can use the application.
    session_policy = _policy(root, "account-session-policy", "account")
    _rule(
        session_policy,
        "permit-authenticated-session",
        "Permit",
        action="session",
        when=_authenticated(),
    )

    # 3. Items
    items = _policy(root, "items-policy", "item")

    # Hidden items (moderation) are visible only to staff.
    _rule(items, "deny-hidden-item-read", "Deny", action="read",
          when=_all(_hidden_item(), _not(_is_staff())))
    _rule(items, "deny-hidden-item-like", "Deny", action="like",
          when=_all(_hidden_item(), _not(_is_staff())))
    _rule(items, "deny-hidden-item-buy", "Deny", action="buy",
          when=_all(_hidden_item(), _not(_is_staff())))
    # Sellers cannot edit a hidden item, so moderated content cannot be changed.
    _rule(items, "deny-hidden-item-update", "Deny", action="update",
          when=_all(_hidden_item(), _not(_is_staff())))

    _rule(items, "deny-buy-own-item", "Deny", action="buy", when=_owner())

    _rule(items, "permit-item-read", "Permit", action="read")
    _rule(items, "permit-item-create", "Permit", action="create", when=_authenticated())
    _rule(items, "permit-item-like", "Permit", action="like", when=_authenticated())
    _rule(items, "permit-item-buy", "Permit", action="buy", when=_authenticated())
    _rule(items, "permit-item-update-owner", "Permit", action="update", when=_owner())
    _rule(items, "permit-item-delete-owner", "Permit", action="delete", when=_owner())
    _rule(items, "permit-item-delete-admin", "Permit", action="delete", role="admin")
    # NEW: direct removal of an item from a report. Admin only.
    _rule(items, "permit-item-report-remove-admin", "Permit",
          action="report_remove", role="admin")

    # 4. Reports
    reports = _policy(root, "report-policy", "report")

    _rule(reports, "deny-self-report", "Deny", action="create", when=_owner())

    # Moderators cannot report or decide on staff accounts.
    _rule(reports, "deny-moderator-report-staff", "Deny",
          action="create", role="moderator", when=_target_is_staff())
    _rule(reports, "deny-moderator-decide-staff", "Deny",
          action="decide", role="moderator", when=_target_is_staff())
    _rule(
        reports,
        "permit-moderator-decide-pending",
        "Permit",
        action="decide",
        role="moderator",
        when=_status_is("pending")
    )
    _rule(reports, "permit-create-report", "Permit",
          action="create", when=_authenticated())

    _rule(reports, "permit-moderator-read-reports", "Permit",
          action="read", role="moderator", when=_status_is("pending", "for_admin"))
    _rule(reports, "permit-admin-read-escalated", "Permit",
          action="read", role="admin", when=_status_is("for_admin"))
    _rule(reports, "permit-admin-escalated-decide", "Permit",
          action="escalated_decide", role="admin", when=_status_is("for_admin"))

    _rule(reports, "permit-moderator-create-escalated", "Permit",
          action="create_escalated", role="moderator")
    _rule(reports, "permit-admin-create-escalated", "Permit",
          action="create_escalated", role="admin")

    # 5. Administrative actions
    admin = _policy(root, "admin-action-policy", "admin_action")

    # Admins cannot act on their own account.
    for action in ("ban", "unban", "delete_user", "revert"):
        _rule(admin, f"deny-admin-self-{action}", "Deny",
              action=action, role="admin", when=_owner())

    for action in ("view", "ban", "revert", "unban", "delete_user"):
        _rule(admin, f"permit-admin-{action}", "Permit",
              action=action, role="admin")

    # 6. Moderator applications
    petitions = _policy(root, "mod-petition-policy", "mod_petition")

    _rule(petitions, "permit-user-create-petition", "Permit",
          action="create", role="user", when=_authenticated())
    _rule(petitions, "permit-owner-read-petition", "Permit",
          action="read", when=_owner())
    _rule(petitions, "permit-admin-read-petitions", "Permit",
          action="read", role="admin")
    _rule(petitions, "permit-owner-delete-petition", "Permit",
          action="delete", when=_owner())
    # Only applications from regular users can be reviewed.
    _rule(petitions, "permit-admin-review-petitions", "Permit",
          action="review", role="admin",
          when=_eq("applicant_role", XACML_RESOURCE, "user"))

    # 7. Public profiles
    profiles = _policy(root, "user-profile-policy", "user_profile")

    # Suspended profile: hidden from everyone except the owner and moderators.
    # According to the privacy matrix, admins cannot see it either.
    _rule(profiles, "deny-suspended-profile-to-others", "Deny", action="read",
          when=_all(
              _resource_suspended(),
              _not(_owner()),
              _not(_eq("role", XACML_SUBJECT, "moderator")),
          ))
    _rule(profiles, "permit-public-profile-read", "Permit", action="read")

    # 8. Personal data (PII)
    pii = _policy(root, "user-pii-policy", "user_pii")

    _rule(pii, "deny-anonymous-pii", "Deny", when=_authenticated(False))
    for action in ("read", "update", "delete"):
        _rule(pii, f"permit-owner-pii-{action}", "Permit",
              action=action, when=_owner())

    # 9. Registration and login
    users = _policy(root, "user-policy", "user")

    _rule(users, "permit-anonymous-registration", "Permit",
          action="create", role="anonymous")
    _rule(users, "deny-login-suspended", "Deny",
          action="login", when=_resource_suspended())
    _rule(users, "permit-login", "Permit", action="login")

    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body


# ============================================================
# XML request (PDP)
# ============================================================

# Maps XACML attribute ids to the keys produced by subject_from_user().
_SUBJECT_KEYS = {
    "role": "role",
    "subject-id": "id",
    "authenticated": "authenticated",
    "is_banned": "is_banned",
    "is_blacklisted": "is_blacklisted",
}


def _add_attribute(category_el, attribute_id: str, value: Any) -> None:
    """Adds one attribute with a single string value to a category element."""
    attribute = _el(category_el, "Attribute", {
        "AttributeId": attribute_id,
        "IncludeInResult": "false",
    })
    _el(attribute, "AttributeValue", {"DataType": XSD_STRING}).text = str(value)


def _build_request_xml(
    subject: dict[str, Any],
    action: str,
    resource_type: str,
    resource: dict[str, Any],
) -> str:
    """Builds an XACML 3.0 XML Request with subject, action and resource categories."""
    request = ET.Element(_tag("Request"), {
        "ReturnPolicyIdList": "false",
        "CombinedDecision": "false",
    })

    subject_category = _el(request, "Attributes", {"Category": XACML_SUBJECT})
    for attribute_id, subject_key in _SUBJECT_KEYS.items():
        _add_attribute(subject_category, attribute_id, subject[subject_key])

    action_category = _el(request, "Attributes", {"Category": XACML_ACTION})
    _add_attribute(action_category, "action-id", action)

    resource_category = _el(request, "Attributes", {"Category": XACML_RESOURCE})
    _add_attribute(resource_category, "resource-type", resource_type)

    for key, value in (resource or {}).items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        _add_attribute(resource_category, str(key), value)

    return ET.tostring(request, encoding="unicode")


def _parse_decision(response_text: str) -> Optional[str]:
    """Returns the Decision value (Permit, Deny, NotApplicable, Indeterminate) from an XML Response."""
    root = ET.fromstring(response_text)
    decision = root.find(f".//{_tag('Decision')}")
    if decision is None or not decision.text:
        return None
    return decision.text.strip()


def xacml_decide(
    subject: dict[str, Any],
    action: str,
    resource_type: str,
    resource: dict[str, Any],
) -> bool:
    """Requests a decision from AuthzForce. Returns True only for Permit."""
    if not AUTHZFORCE_URL:
        log.error("AuthzForce is not initialized: denying.")
        return False

    request_xml = _build_request_xml(subject, action, resource_type, resource)

    try:
        response = httpx.post(
            AUTHZFORCE_URL,
            content=request_xml,
            headers={
                "Content-Type": "application/xml",
                "Accept": "application/xml",
            },
            timeout=5.0,
        )

        if response.status_code >= 400:
            # The body says what AuthzForce rejected. Keep it in the log.
            log.error(
                "AuthzForce returned HTTP %s for action=%s resource=%s: %s",
                response.status_code, action, resource_type,
                response.text[:1000] or "<empty body>",
            )
            return False

        
        decision = _parse_decision(response.text)

        log.warning(
            "XACML DEBUG: decision=%s subject=%s role=%s "
            "action=%s resource_type=%s resource_attributes=%s",
            decision,
            subject.get("id"),
            subject.get("role"),
            action,
            resource_type,
            resource,
        )

        if decision is None:
            log.error(
                "AuthzForce responded without a decision: %s",
                response.text[:1000],
            )
            return False

        if decision != "Permit":
            log.error(
                "XACML DENIED: decision=%s subject=%s role=%s "
                "action=%s resource_type=%s response=%s",
                decision,
                subject.get("id"),
                subject.get("role"),
                action,
                resource_type,
                response.text[:2000],
            )

        return decision == "Permit"

    except Exception:
        log.exception("Error querying AuthzForce: action=%s resource=%s",
                      action, resource_type)
        return False


def _self_test() -> None:
    """
    Checks that the published policy is the one the PDP evaluates.
    If the PDP does not use our PolicySet, it returns NotApplicable and every
    request is denied. This test fails at startup instead of denying silently.
    """
    anon = subject_from_user(None)
    member = {"id": "self-test-user", "role": "user", "authenticated": "true",
              "is_banned": "false", "is_blacklisted": "false"}
    moderator = {"id": "self-test-mod", "role": "moderator", "authenticated": "true",
                 "is_banned": "false", "is_blacklisted": "false"}
    # NEW: admin subject for the report_remove and delete cases.
    admin = {"id": "self-test-admin", "role": "admin", "authenticated": "true",
             "is_banned": "false", "is_blacklisted": "false"}
    suspended = {"id": "self-test-susp", "role": "user", "authenticated": "true",
                 "is_banned": "false", "is_blacklisted": "true"}
    visible = {"owner_id": "someone", "is_blacklisted": "false"}
    hidden = {"owner_id": "someone", "is_blacklisted": "true"}
    no_flags = {"is_banned": "false", "is_blacklisted": "false"}

    cases = [
        ("anonymous reads visible item", anon, "read", "item", visible, True),
        ("anonymous reads hidden item", anon, "read", "item", hidden, False),
        ("moderator reads hidden item", moderator, "read", "item", hidden, True),
        ("anonymous creates item", anon, "create", "item", {}, False),
        ("user creates item", member, "create", "item", {}, True),
        ("suspended account creates item", suspended, "create", "item", {}, False),
        ("suspended account reads visible item", suspended, "read", "item", visible, True),
        ("anonymous logs in", anon, "login", "user", no_flags, True),
        # NEW: report_remove and admin delete.
        ("admin deletes any item", admin, "delete", "item", visible, True),
        ("admin removes item from a report", admin, "report_remove", "item", visible, True),
        ("moderator cannot remove item from a report", moderator, "report_remove", "item", visible, False),
        ("user cannot remove item from a report", member, "report_remove", "item", visible, False),
        ("user cannot delete someone else's item", member, "delete", "item", visible, False),
    ]

    failures = [
        label for label, subject, action, rtype, resource, expected in cases
        if xacml_decide(subject, action, rtype, resource) != expected
    ]

    if failures:
        raise RuntimeError(
            "AuthzForce self-test failed: " + "; ".join(failures)
            + ". The PDP is not evaluating the published PolicySet, "
            "or the request format is wrong. Check the log lines 'XACML ...' above."
        )
    log.info("AuthzForce self-test passed (%d cases).", len(cases))


# ============================================================
# Network and publication to AuthzForce
# ============================================================

def _resolve_href(href: str, base_url: str) -> str:
    """Resolves an absolute or relative href returned by AuthzForce."""
    return urljoin(base_url.rstrip("/") + "/", href).rstrip("/")


def _find_href(xml_text: str) -> Optional[str]:
    """Returns the first href attribute found in an XML response."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    for element in root.iter():
        href = element.attrib.get("href")
        if href:
            return href
    return None


def _bind_root_policy(domain_path: str) -> None:
    """
    Makes the PDP evaluate our PolicySet by setting rootPolicyRefExpression.

    The update document contains only the feature flags the PDP already has
    and the new expression. The PDP rejected applicablePolicies in this
    position, so that element is not sent.
    """
    url = f"{domain_path}/pap/pdp.properties"

    current = httpx.get(url, timeout=5.0)
    current.raise_for_status()
    current_root = ET.fromstring(current.text)

    def q(name: str) -> str:
        return f"{{{AUTHZ_REST_NS}}}{name}"

    update = ET.Element(q("pdpPropertiesUpdate"))

    for feature in current_root.findall(q("feature")):
        update.append(feature)

    ET.SubElement(update, q("rootPolicyRefExpression")).text = POLICY_SET_ID

    put = httpx.put(
        url,
        content=ET.tostring(update, encoding="unicode"),
        headers={"Content-Type": "application/xml"},
        timeout=10.0,
    )
    if put.status_code >= 400:
        raise RuntimeError(
            f"AuthzForce rejected the root policy binding ({put.status_code}): "
            + put.text[:1000]
        )

    log.info("PDP rootPolicyRefExpression set to %s.", POLICY_SET_ID)


def init_authzforce() -> None:
    """
    Waits for AuthzForce, finds or creates the domain, publishes a new
    PolicySet version, binds it to the PDP and runs the self-test.
    """
    global AUTHZFORCE_URL

    domains_url = f"{AUTHZFORCE_BASE_URL}/domains"
    log.info("Checking AuthzForce server at %s", domains_url)

    response = None
    for attempt in range(30):
        try:
            candidate = httpx.get(domains_url, timeout=3.0)
            candidate.raise_for_status()
            response = candidate
            break
        except httpx.HTTPError as exc:
            if attempt == 29:
                raise RuntimeError(
                    f"AuthzForce is not available at {domains_url}"
                ) from exc
            log.warning("AuthzForce not responding yet (attempt %s/30).", attempt + 1)
            time.sleep(2)

    href = _find_href(response.text)

    if href:
        domain_path = _resolve_href(href, domains_url)
        log.info("Existing domain: %s", domain_path)
    else:
        xml_domain = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<domainProperties '
            'xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5">'
            '<description>Marketplace</description>'
            '</domainProperties>'
        )
        domain_response = httpx.post(
            domains_url,
            headers={"Content-Type": "application/xml"},
            content=xml_domain,
            timeout=10.0,
        )
        domain_response.raise_for_status()
        href = _find_href(domain_response.text)
        if not href:
            raise RuntimeError(
                "AuthzForce did not return the link of the created domain: "
                + domain_response.text[:1000]
            )
        domain_path = _resolve_href(href, domains_url)
        log.info("New domain created: %s", domain_path)

    AUTHZFORCE_URL = f"{domain_path}/pdp"

    # A new version on every start avoids deleting a policy that the PDP may
    # be using, which AuthzForce rejects with HTTP 500.
    version = f"2.1.{int(time.time())}"

    policy_response = httpx.post(
        f"{domain_path}/pap/policies",
        headers={"Content-Type": "application/xml"},
        content=_build_policy_set(version),
        timeout=15.0,
    )
    if policy_response.status_code >= 400:
        raise RuntimeError(
            f"AuthzForce rejected the PolicySet {version} "
            f"({policy_response.status_code}): {policy_response.text[:1000]}"
        )
    log.info("XACML PolicySet published as %s/%s.", POLICY_SET_ID, version)

    _bind_root_policy(domain_path)
    _self_test()


# ============================================================
# PIP: subject and resource attributes
# ============================================================

def _bool_str(value: Any) -> str:
    return "true" if bool(value) else "false"


def role_of(user: User) -> str:
    """Role as a lowercase string, whether it is an Enum or a plain string."""
    role = user.role
    return (role.value if hasattr(role, "value") else str(role)).lower()


def _status_str(status: Any) -> str:
    return (status.value if hasattr(status, "value") else str(status)).lower()


def subject_from_user(user: Optional[User]) -> dict[str, Any]:
    """Builds the XACML subject. Anonymous users get the 'anonymous' role."""
    if user is None:
        return {
            "id": "anon",
            "role": "anonymous",
            "authenticated": "false",
            "is_banned": "false",
            "is_blacklisted": "false",
        }
    return {
        "id": str(user.id),
        "role": role_of(user),
        "authenticated": "true",
        "is_banned": _bool_str(user.is_banned),
        "is_blacklisted": _bool_str(user.is_blacklisted),
    }


def account_attrs(user: User) -> dict[str, Any]:
    return {"owner_id": str(user.id)}


def login_attrs(user: User) -> dict[str, Any]:
    return {
        "is_banned": _bool_str(user.is_banned),
        "is_blacklisted": _bool_str(user.is_blacklisted),
    }


def item_attrs(item: Item) -> dict[str, Any]:
    return {
        "owner_id": str(item.seller_id),
        "is_blacklisted": _bool_str(item.is_blacklisted),
    }


def user_profile_attrs(user: User) -> dict[str, Any]:
    return {
        "owner_id": str(user.id),
        "is_banned": _bool_str(user.is_banned),
        "is_blacklisted": _bool_str(user.is_blacklisted),
    }


def user_pii_attrs(user: User) -> dict[str, Any]:
    return {"owner_id": str(user.id)}


def admin_target_attrs(target_user_id) -> dict[str, Any]:
    return {"owner_id": str(target_user_id)}


def report_create_attrs(target_user_id, target_role: str) -> dict[str, Any]:
    """target_role is required: moderator rules depend on it."""
    return {"owner_id": str(target_user_id), "target_role": target_role}


def user_report_attrs(report: UserReport, target_role: str) -> dict[str, Any]:
    return {
        "owner_id": str(report.target_user_id),
        "reporter_id": str(report.reporter_id),
        "status": _status_str(report.status),
        "target_role": target_role,
    }


def item_report_attrs(report: ItemReport, item: Item, seller_role: str) -> dict[str, Any]:
    return {
        "owner_id": str(item.seller_id),
        "reporter_id": str(report.reporter_id),
        "status": _status_str(report.status),
        "target_role": seller_role,
    }


def petition_review_attrs(applicant: User) -> dict[str, Any]:
    return {
        "owner_id": str(applicant.id),
        "applicant_role": role_of(applicant),
    }


# ============================================================
# PEP
# ============================================================

def can(
    user: Optional[User],
    action: str,
    resource_type: str,
    resource: dict,
) -> bool:
    """Returns True/False without raising. Use it to filter lists."""
    return xacml_decide(subject_from_user(user), action, resource_type, resource)


def enforce(
    user: Optional[User],
    action: str,
    resource_type: str,
    resource: dict,
) -> None:
    """Raises 401 when there is no session and 403 when there is no Permit."""
    subject = subject_from_user(user)
    if xacml_decide(subject, action, resource_type, resource):
        return

    audit.warning(
        "DENY subject=%s role=%s action=%s resource=%s",
        subject["id"], subject["role"], action, resource_type,
    )

    if user is None:
        raise HTTPException(status_code=401, detail="Debes iniciar sesión")
    raise HTTPException(status_code=403, detail="Permission denied")