from tcsfw.claim_set import Claim, EncryptionClaim, UpdateClaim, ReleaseClaim, BOMClaim, \
    AuthenticationClaim, AvailabilityClaim, PermissionClaim, \
    NoVulnerabilitiesClaim, ProtocolClaim
from tcsfw.basics import HostType
from tcsfw.requirement import Specification
from tcsfw.selector import ConnectionSelector, HostSelector, Select, ServiceSelector


class DefaultSpecification(Specification):
    """The default requirement specification"""
    def __init__(self):
        super().__init__("default", "Default requirements")
        self.short_infos = True

        # Categories and claims from 2023 article:

        # Security design

        self.no_unexpected_nodes = self._req(
            "no-unexp-nodes",
            # NOTE: HostSelector picks also the unexpected nodes, which will have expected=False
            Select.host(unexpected=True) ^ Claim.expected("Network nodes are defined"))

        self.no_unexpected_services = self._req(
            "no-unexp-services",
            Select.service(unexpected=True) ^ Claim.expected("Network services are defined"))

        self.no_unexpected_connections = self._req(
            "no-unexp-connections",
            Select.connection(unexpected=True) ^ Claim.expected("Network connections are defined"))

        # Interface security

        self.protocol_best = self._req(
            "protocol-best",
            # NOTE: HTTP redirect should only be viable for HTTP!
            Select.service() ^ Claim.name("Use protocol best practices",
                                           Claim.protocol_best_practices() | Claim.http_redirect()))
        # Web security

        self.web_best = self._req(
            "web-best",
            # "Web best practises are used",
            Select.service().web() ^ Claim.name("Web best practises are used",
                                                Claim.web_best_practices() | Claim.http_redirect()))
        # Authentication

        self.service_authenticate = self._req(
            "service-auth",
            Select.service().direct() ^ Claim.name("Services are authenticated",
                                                   Claim.authentication() | Claim.http_redirect()))
        # Data protection

        self.connection_encrypt = self._req(
            "conn-encrypt",
            Select.connection() ^ Claim.name("Connections are encrypted",
                                             Claim.encryption() | Claim.http_redirect()))

        self.private_data = self._req(
            "private-data",
            Select.data() ^ Claim.name("Private data is defined", Claim.sensitive_data()))


        self.privacy_policy = self._req(
            "privacy-policy",
            Select.system() ^ Claim.available("privacy-policy") % "Privacy policy is available")

        # Updates

        self.updates = self._req(
            "updates",
            Select.software() ^ Claim.updateable("Automated software updates"))

        self.sbom = self._req(
            "sbom",
            Select.software() ^ Claim.sbom("SBOM is defined"))

        self.no_known_vulnerabilities = self._req(
            "no-known-vuln",
            Select.software() ^ Claim.no_vulnerabilities("No vulnerabilities are known"))

        # Vulnerability process

        self.security_policy = self._req(
            "security-policy",
            Select.system() ^ Claim.available("security-policy") % "Security policy is available")

        self.release_info = self._req(
            "release-info",
            Select.software() ^ Claim.releases("Release history is available"))

        # Mobile applications

        self.permissions = self._req(
            "permissions",
            Select.host().type_of(HostType.MOBILE) / Select.software()
            ^ Claim.permissions("Permissions are appropriate"))


DEFAULT = DefaultSpecification()
