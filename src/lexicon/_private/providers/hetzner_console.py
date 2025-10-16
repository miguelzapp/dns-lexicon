"""Module provider for Hetzner Console (RRSet API)"""

import json
import logging
from argparse import ArgumentParser
from typing import List, Dict, Any, Optional, Iterable

import requests

from lexicon.exceptions import AuthenticationError
from lexicon.interfaces import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)


class Provider(BaseProvider):
    """
    Implements the Hetzner DNS Provider using the new RRSet-based API at https://api.hetzner.cloud.
    This implementation manages Resource Record Sets (RRSets), not legacy individual /records.

    NOTE: It does not work for "dns.hetzner.com" offers (see hetzner provider).
    """

    API_VERSION = "1.0"

    @staticmethod
    def get_nameservers() -> List[str]:
        return ["ns.hetzner.com"]

    @staticmethod
    def configure_parser(parser: ArgumentParser) -> None:
        parser.add_argument("--auth-token", help="Specify Hetzner Console API token")

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id: Optional[str] = None
        self.api_endpoint = "https://api.hetzner.cloud/v1"

    def authenticate(self):
        zone = self._get_zone_by_domain(self.domain)
        self.domain_id = zone["id"]

    def cleanup(self) -> None:
        pass

    def create_record(self, rtype: str, name: str, content: str):
        """
        Create a DNS record value inside its RRSet.
        If an identical value already exists in the RRSet, do nothing.
        """
        rr_name = self._get_record_name(self.domain, name)

        # If exact record already exists, no-op (Lexicon convention)
        existing = self.list_records(rtype=rtype, name=name, content=content)
        if existing:
            for record in existing:
                LOGGER.warning(
                    "Duplicate record %s %s %s with id %s",
                    rtype,
                    name,
                    content,
                    record.get("id"),
                )
            return True

        # Add value to RRSet (auto-creates RRSet if missing)
        payload: Dict[str, Any] = {
            "records": [{"value": self._format_value(rtype, content)}],
        }
        ttl = self._get_lexicon_option("ttl")
        if ttl:
            payload["ttl"] = int(ttl)

        self._post(self._rrset_action_path(rr_name, rtype, "add_records"), payload)
        return True

    def list_records(
        self,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ):
        """
        List records (flattened from RRSets), filterable by type, name and content.
        Returns a list of Lexicon-style record dicts.
        """
        assert self.domain_id, "authenticate() must be called before list_records()."

        query: Dict[str, Any] = {}
        if name:
            query["name"] = self._get_record_name(self.domain, name)
        if rtype:
            # Hetzner API accepts multiple type filters; a single one is fine here.
            query["type"] = rtype

        payload = self._get(f"/zones/{self.domain_id}/rrsets", query)
        rrsets: Iterable[Dict[str, Any]] = payload.get("rrsets", [])

        results = []
        for rrset in rrsets:
            rr_name = rrset["name"]
            rr_type = rrset["type"]
            rr_ttl = rrset.get("ttl")

            for rec in rrset.get("records", []):
                raw_value = rec.get("value")
                record = {
                    # synthesized id lets us target a specific value within an RRSet
                    "id": self._synth_record_id(rr_name, rr_type, raw_value),
                    "name": self._full_name(rr_name),
                    "type": rr_type,
                    "content": self._normalize_value(rr_type, raw_value),
                }
                if rr_ttl is not None:
                    record["ttl"] = rr_ttl
                results.append(record)

        # Client-side filtering for content (and for safety if server filters evolve)
        results = self._filter_records(
            results, rtype, name if name is not None else None, content
        )
        return results

    def _filter_records(self, records, rtype=None, name=None, content=None):
        def _match(record):
            if rtype is not None and record["type"] != rtype:
                return False
            if name is not None and record["name"] != self._full_name(name):
                return False
            if content is not None and record["content"] != content:
                return False
            return True

        return [r for r in records if _match(r)]

    def update_record(self, identifier, rtype=None, name=None, content=None):
        """
        Update a record.
        Behavior:
          - If `identifier` encodes name/type/value, replace just that value within the RRSet with `content`.
          - Else, when name+type provided, replace the entire RRSet's records with a single value = `content`.
          - Else (identifier is RRSet-level: "name/type"), replace RRSet with single `content`.
        """
        assert self.domain_id, "authenticate() must be called before update_record()."
        if not content:
            raise Exception("update_record requires `content` (new value).")

        # Resolve target
        if identifier:
            id_name, id_type, id_value = self._parse_record_id(identifier)
            if id_name and id_type and id_value:
                # Replace one value within existing RRSet
                current = self._get_rrset(id_name, id_type)
                new_values = [
                    r["value"]
                    for r in current.get("records", [])
                    if r.get("value") != id_value
                ]
                new_values.append(self._format_value(rtype or id_type, content))
                unique_values = sorted(set(new_values))
                payload = {"records": [{"value": v} for v in unique_values]}
                self._post(
                    self._rrset_action_path(id_name, id_type, "set_records"), payload
                )
                return True
            elif id_name and id_type:
                # Identifier refers to RRSet; replace entirely
                payload = {
                    "records": [
                        {"value": self._format_value(rtype or id_type, content)}
                    ]
                }
                self._post(
                    self._rrset_action_path(id_name, id_type, "set_records"), payload
                )
                return True

        # No/ambiguous identifier: fall back to name+type disambiguation like Lexicon does
        if rtype and name:
            rr_name = self._get_record_name(self.domain, name)
            matches = self.list_records(rtype=rtype, name=name)
            if len(matches) == 1:
                payload = {"records": [{"value": self._format_value(rtype, content)}]}
                self._post(
                    self._rrset_action_path(rr_name, rtype, "set_records"), payload
                )
                return True
            elif len(matches) < 1:
                raise Exception(
                    "No records found matching type and name - won't update"
                )
            else:
                raise Exception(
                    "Multiple records found matching type and name - won't update"
                )

        raise Exception(
            "Insufficient data to update record: provide identifier or (rtype and name)."
        )

    def delete_record(
        self,
        identifier: Optional[str] = None,
        rtype: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
    ):
        """
        Delete existing record(s).
        Behavior:
          - If `identifier` specifies name/type/value: remove that value from the RRSet.
          - If `identifier` specifies name/type only: delete the entire RRSet.
          - Else, if rtype+name+content: remove that single value from the RRSet.
          - Else, if rtype+name: delete the entire RRSet.
          - Else, if only content: remove all occurrences of that content under the zone (rare).
        """
        assert self.domain_id, "authenticate() must be called before delete_record()."

        if identifier:
            id_name, id_type, maybe_value = self._parse_record_id(identifier)
            if id_name and id_type and maybe_value:
                # remove a single value (value is already in stored form; send as-is)
                payload = {"records": [{"value": maybe_value}]}
                self._post(
                    self._rrset_action_path(id_name, id_type, "remove_records"), payload
                )
                return True
            if id_name and id_type:
                # delete entire RRSet
                self._delete(self._rrset_path(id_name, id_type))
                return True

        # No identifier path
        if rtype and name and content:
            rr_name = self._get_record_name(self.domain, name)
            payload = {"records": [{"value": self._format_value(rtype, content)}]}
            self._post(
                self._rrset_action_path(rr_name, rtype, "remove_records"), payload
            )
            return True

        if rtype and name:
            rr_name = self._get_record_name(self.domain, name)
            self._delete(self._rrset_path(rr_name, rtype))
            return True

        if content:
            # Fallback: remove that content wherever it appears under the zone (best-effort)
            all_of_type = (
                self.list_records(rtype=rtype) if rtype else self.list_records()
            )
            targets = [r for r in all_of_type if r["content"] == content]
            for r in targets:
                n, t, v = self._parse_record_id(r["id"])
                if n and t and v:
                    payload = {"records": [{"value": v}]}
                    self._post(self._rrset_action_path(n, t, "remove_records"), payload)
            return True

        # Nothing to do
        return True

    def _request(
        self,
        action: str = "GET",
        url: str = "/",
        data: Optional[dict] = None,
        query_params: Optional[dict] = None,
    ):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}
        response = requests.request(
            action,
            self.api_endpoint + url,
            params=query_params,
            data=json.dumps(data) if data else None,
            headers={
                "Authorization": f"Bearer {self._get_provider_option('auth_token')}",  # fixed quotes
                "Content-Type": "application/json",
            },
        )
        # Raise for any non-2xx
        response.raise_for_status()
        # Some DELETE/201-action responses may be empty; guard accordingly
        if response.text:
            return response.json()
        return {}

    def _get_zone_by_domain(self, domain: str) -> dict:
        """
        Resolve zone by domain name to get its zone ID.
        """
        payload = self._get("/zones", {"name": domain})
        zones = payload.get("zones", [])
        for zone in zones:
            if zone.get("name") == domain:
                return zone
        raise AuthenticationError(f"No zone was found in account matching {domain}")

    def _get_record_name(self, domain: str, record_name: str) -> str:
        """
        Convert to RRSet name rules: relative to zone if under the managed domain,
        otherwise keep FQDN. Do not include trailing dot.
        """
        record_name = record_name.rstrip(".")
        if record_name.endswith(domain):
            record_name = self._relative_name(record_name)
        # Hetzner expects '@' for apex (Lexicon already does relative_name('example.com') -> '@')
        return record_name

    def _rrset_path(self, rr_name: str, rr_type: str) -> str:
        return f"/zones/{self.domain_id}/rrsets/{rr_name}/{rr_type}"

    def _rrset_action_path(self, rr_name: str, rr_type: str, action: str) -> str:
        return f"{self._rrset_path(rr_name, rr_type)}/actions/{action}"

    def _get_rrset(self, rr_name: str, rr_type: str) -> dict:
        return self._get(self._rrset_path(rr_name, rr_type))

    @staticmethod
    def _synth_record_id(rr_name: str, rr_type: str, value: str) -> str:
        # unique within a zone, good enough for Lexicon operations
        return f"{rr_name}/{rr_type}/{value}"

    @staticmethod
    def _parse_record_id(identifier: str):
        """
        Accepts:
          - "name/type/value" -> (name, type, value)
          - "name/type" -> (name, type, None)
          - otherwise -> (None, None, None)
        """
        parts = identifier.split("/")
        if len(parts) >= 3:
            return parts[0], parts[1], "/".join(parts[2:])
        if len(parts) == 2:
            return parts[0], parts[1], None
        return None, None, None

    def _format_value(self, rtype: Optional[str], value: str) -> str:
        """Format value per Hetzner expectations."""
        if rtype == "TXT":
            v = value
            # Quote if not already quoted
            is_quoted = len(v) >= 2 and v[0] == '"' and v[-1] == '"'
            if not is_quoted:
                v = v.replace("\\", "\\\\").replace('"', r"\"")
                v = f'"{v}"'
            return v
        return value

    def _normalize_value(self, rtype: Optional[str], value: str) -> str:
        """Normalize value for Lexicon filters: strip TXT quotes when possible."""
        if rtype == "TXT":
            if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                inner = value[1:-1]
                inner = inner.replace(r"\"", '"').replace("\\\\", "\\")
                return inner
        return value

    @staticmethod
    def _pretty_json(data):
        return json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    def _hetzner_record_to_lexicon_record(self, hetzner_record):
        """
        (Unused now) Kept for compatibility if referenced elsewhere.
        The new flow builds Lexicon records directly from RRSet responses.
        """
        lexicon_record = {
            "id": hetzner_record["id"],
            "name": self._full_name(hetzner_record["name"]),
            "content": hetzner_record["value"],
            "type": hetzner_record["type"],
        }
        if "ttl" in hetzner_record:
            lexicon_record["ttl"] = hetzner_record["ttl"]
        return lexicon_record
