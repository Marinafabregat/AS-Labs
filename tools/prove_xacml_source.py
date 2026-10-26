"""
Proves that the decision comes from the published PolicySet.
Asks AuthzForce for the decision AND the identifiers of the policies that produced it.
Run from the project root with AuthzForce up:
    AUTHZFORCE_BASE_URL=http://localhost:8080/authzforce-ce python3 tools/prove_xacml_source.py
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

import authz  # noqa: E402

ANON = {
    "id": "anon", "role": "anonymous", "authenticated": "false",
    "is_banned": "false", "is_blacklisted": "false",
}


def main() -> int:
    authz.init_authzforce()

    # Anonymous user reading a hidden item: the expected answer is Deny.
    body = authz._build_request_xml(
        ANON, "read", "item", {"owner_id": "someone", "is_blacklisted": "true"}
    )
    body = body.replace('ReturnPolicyIdList="false"', 'ReturnPolicyIdList="true"')

    response = httpx.post(
        authz.AUTHZFORCE_URL,
        content=body,
        headers={"Content-Type": "application/xml", "Accept": "application/xml"},
        timeout=5.0,
    )
    print(f"HTTP {response.status_code}")

    root = ET.fromstring(response.text)
    for element in root.iter():
        name = element.tag.split("}")[-1]
        if name in ("Decision", "PolicySetIdReference", "PolicyIdReference"):
            print(f"{name}: {element.text}")

    print("\nRaw response (first 1500 chars):")
    print(response.text[:1500])

    decided_by_us = "marketplace-policyset" in response.text
    print("\nRESULT:", "decision produced by marketplace-policyset"
          if decided_by_us else "NOT produced by marketplace-policyset")
    return 0 if decided_by_us else 1


if __name__ == "__main__":
    sys.exit(main())