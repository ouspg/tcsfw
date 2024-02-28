from tcsfw.claim import Claim
from tcsfw.claim_set import Claims, EncryptionClaim, UpdateClaim, ReleaseClaim, BOMClaim, \
    AuthenticationClaim, AvailabilityClaim, PermissionClaim, \
    NoVulnerabilitiesClaim, ProtocolClaim
from tcsfw.basics import HostType
from tcsfw.requirement import Specification
from tcsfw.selector import ConnectionSelector, HostSelector, Select, ServiceSelector


def req(text: str, extends: Claim):
    return text, None, [extends]


class DefaultSpecification(Specification):
    """The default requirement specification"""
    def __init__(self):
        super().__init__("default", "Default requirements")
        self.short_infos = True

        # Categories and claims from 2023 article

        # Security design
        # [x] Network nodes are defined
        self.no_unexpected_nodes = self._req(
            "no-unexp-nodes",
            # NOTE: HostSelector picks also the unexpected nodes, which will have expected=False
            Select.host(unexpected=True) ^ Claims.name("Network nodes are defined", Claims.EXPECTED))
        # [x] Network services are defined
        self.no_unexpected_services = self._req(
            "no-unexp-services",
            Select.service(unexpected=True) ^ Claims.name("Network services are defined", Claims.EXPECTED))
        # [ ] Network connections are defined
        self.no_unexpected_connections = self._req(
            "no-unexp-connections",
            Select.connection(unexpected=True) ^ Claims.name("Network connections are defined", Claims.EXPECTED))
        # Interface security
        # [ ] Protocol best practises are used
        self.protocol_best = self._req(
            "protocol-best",
            # NOTE: HTTP redirect should only be viable for HTTP!
            Select.service() ^ Claims.name("Use protocol best practices",
                                           ProtocolClaim() | Claims.HTTP_REDIRECT))
        # Web security
        # [ ] Web best practises are used
        self.web_best = self._req(
            "web-best",
            # "Web best practises are used",
            Select.service().web() ^ Claims.name("Web best practises are used",
                                                 Claims.WEB_BEST_PRACTICE | Claims.HTTP_REDIRECT))
        # Authentication
        # [x] Services are authenticated
        self.service_authenticate = self._req(
            "service-auth",
            Select.service().direct() ^ Claims.name("Services are authenticated",
                                                     AuthenticationClaim() | Claims.HTTP_REDIRECT))
        # Data protection
        # [x] Connections are encrypted
        self.connection_encrypt = self._req(
            "conn-encrypt",
            Select.connection() ^ Claims.name("Connections are encrypted",
                                              EncryptionClaim() | Claims.HTTP_REDIRECT))
        # [ ] Private data is defined
        self.private_data = self._req(
            "private-data",
            Select.DATA ^ Claims.name("Private data is defined", Claims.SENSITIVE_DATA))

        # [x] Privacy policy is defined
        self.privacy_policy = self._req(
            "privacy-policy",
            Select.system() ^ AvailabilityClaim("privacy-policy").name("Privacy policy is available"))
        # Updates
        # [x] Updates are secure and automatic
        self.updates = self._req(
            "updates",
            Select.SOFTWARE ^ UpdateClaim("Automated software updates"))
        # [x] SBOM is defined
        self.sbom = self._req(
            "sbom",
            Select.SOFTWARE ^ BOMClaim(description="SBOM is defined"))
        # [x] No vulnerabilities are known
        self.no_known_vulnerabilities = self._req(
            "no-known-vuln",
            Select.SOFTWARE ^ NoVulnerabilitiesClaim(description="No vulnerabilities are known"))
        # Vulnerability process
        # [ ] Security policy is defined
        self.security_policy = self._req(
            "security-policy",
            Select.system() ^ AvailabilityClaim("security-policy").name("Security policy is available"))
        # [x] Release history is available
        self.release_info = self._req(
            "release-info",
            Select.SOFTWARE ^ ReleaseClaim("Release history is available"))
        # Mobile applications
        # [ ] Permissions are appropriate
        self.permissions = self._req(
            "permissions",
            Select.host().type_of(HostType.MOBILE) / Select.SOFTWARE ^
            PermissionClaim().name("Permissions are appropriate"))


DEFAULT = DefaultSpecification()
