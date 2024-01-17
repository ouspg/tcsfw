import enum
from typing import Dict, Optional, Self, List, Any, Tuple, Iterable, Callable, Iterator, TypeVar

from tcsfw.claim import Claim
from tcsfw.property import Properties, PropertyKey
from tcsfw.verdict import Status, Verdict, Verdictable


class Entity:
    """An entity, network node or connection"""
    def __init__(self):
        self.concept_name = "other"
        self.status = Status.UNEXPECTED
        self.properties: Dict[PropertyKey, Any] = {}

    def long_name(self) -> str:
        return self.concept_name

    def reset(self):
        """Reset entity and at least properties"""
        new_p: Dict[PropertyKey, Any] = {}
        for k, v in self.properties.items():
            nv = k.reset(v)
            if nv is not None:
                new_p[k] = nv  # keep a property
        self.properties = new_p

    def set_property(self, key_value: Tuple[PropertyKey, Any]) -> Self:
        """Set a property"""
        self.properties[key_value[0]] = key_value[1]
        return self

    def set_seen_now(self) -> Optional[Verdict]:
        """The entity is seen now, update and return new verdict IF changed"""
        v = self.properties.get(Properties.EXPECTED)
        if self.status == Status.EXPECTED: 
            if v == Verdict.PASS:
                return None  # already ok
            v = Verdict.PASS
        elif self.status == Status.UNEXPECTED:
            if v == Verdict.FAIL:
                return None  # already not ok
            v = Verdict.FAIL
        else:
            return None  # does not matter if seen or not
        self.properties[Properties.EXPECTED] = v
        return v

    def get_expected_verdict(self, default: Optional[Verdict] = Verdict.UNDEFINED) -> Verdict:
        """Get the expected verdict or undefined"""
        return Properties.EXPECTED.get(self.properties) or default

    def get_children(self) -> Iterable['Entity']:
        """Get child entities, if any"""
        return ()

    def get_verdict(self, cache: Dict['Entity', Verdict]) -> Verdict:
        """Get aggregate verdict"""
        v = cache.get(self)
        if v is None:
            for c in self.get_children():
                v = Verdict.resolve(v, c.get_verdict(cache))
            for p in self.properties.values():
                v = Verdict.resolve(v, p.get_verdict()) if isinstance(p, Verdictable) else v
            cache[self] = v = v or Verdict.UNDEFINED
        return v

    def is_relevant(self) -> bool:
        """Is this entity relevant, i.e. not undefined or external?"""
        return True

    def is_host(self) -> bool:
        """Is a host?"""
        return False

    def is_host_reachable(self) -> bool:
        """Are hosts reachable from here"""
        return False

    def iterate(self, relevant_only=True) -> Iterator['Entity']:
        """Iterate this and all child entities"""
        if not relevant_only or self.is_relevant():
            yield self
        for c in self.get_children():
            yield from c.iterate(relevant_only)

    def status_string(self) -> str:
        """Get a status string"""
        st = self.status.value
        exp = self.properties.get(Properties.EXPECTED)
        if exp:
            st = f"{st}|Expected"
        elif exp is not None:
            st = f"{st}|Unexpected"
        return st

    def __repr__(self):
        s = f"{self.status_string()} {self.long_name()}"
        return s

class ClaimAuthority(enum.Enum):
    """Claim or claim status authority"""
    TOOL = "Tool"            # Tool verified
    MANUAL = "Manual"        # Manually verified
    MODEL = "Model"          # Original model claim, not verified


class ClaimStatus:
    def __init__(self, claim: Claim, explanation="", verdict=Verdict.UNDEFINED, authority=ClaimAuthority.MODEL):
        assert claim is not None and verdict is not None
        self.claim = claim
        self.verdict = verdict
        self.explanation = explanation
        self.authority = authority
        self.silent = False
        self.aggregate_of: List[ClaimStatus] = []

    def get_explanation(self) -> str:
        """Get explanation"""
        if isinstance(self.claim, ExplainableClaim):
            return self.claim.explain(self)
        return self.claim.text()


class ExplainableClaim(Claim):
    """A claim which can be explained, with or without status"""
    def explain(self, status: Optional[ClaimStatus]) -> str:
        """Explain the claim and status. Status can be null"""
        if status and status.explanation:
            return status.explanation
        return self.__repr__()

