from tcsfw.claim_set import Claims, EncryptionClaim, UpdateClaim, ReleaseClaim, BOMClaim, \
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
            Select.host(unexpected=True) ^ Claims.name("Network nodes are defined", Claims.EXPECTED))

        self.no_unexpected_services = self._req(
            "no-unexp-services",
            Select.service(unexpected=True) ^ Claims.name("Network services are defined", Claims.EXPECTED))

        self.no_unexpected_connections = self._req(
            "no-unexp-connections",
            Select.connection(unexpected=True) ^ Claims.name("Network connections are defined", Claims.EXPECTED))

        # Interface security

        self.protocol_best = self._req(
            "protocol-best",
            # NOTE: HTTP redirect should only be viable for HTTP!
            Select.service() ^ Claims.name("Use protocol best practices",
                                           ProtocolClaim() | Claims.HTTP_REDIRECT))
        # Web security

        self.web_best = self._req(
            "web-best",
            # "Web best practises are used",
            Select.service().web() ^ Claims.name("Web best practises are used",
                                                 Claims.WEB_BEST_PRACTICE | Claims.HTTP_REDIRECT))
        # Authentication

        self.service_authenticate = self._req(
            "service-auth",
            Select.service().direct() ^ Claims.name("Services are authenticated",
                                                     AuthenticationClaim() | Claims.HTTP_REDIRECT))
        # Data protection

        self.connection_encrypt = self._req(
            "conn-encrypt",
            Select.connection() ^ Claims.name("Connections are encrypted",
                                              EncryptionClaim() | Claims.HTTP_REDIRECT))

        self.private_data = self._req(
            "private-data",
            Select.data() ^ Claims.name("Private data is defined", Claims.SENSITIVE_DATA))


        self.privacy_policy = self._req(
            "privacy-policy",
            Select.system() ^ AvailabilityClaim("privacy-policy").name("Privacy policy is available"))

        # Updates

        self.updates = self._req(
            "updates",
            Select.software() ^ UpdateClaim("Automated software updates"))

        self.sbom = self._req(
            "sbom",
            Select.software() ^ BOMClaim(description="SBOM is defined"))

        self.no_known_vulnerabilities = self._req(
            "no-known-vuln",
            Select.software() ^ NoVulnerabilitiesClaim(description="No vulnerabilities are known"))

        # Vulnerability process

        self.security_policy = self._req(
            "security-policy",
            Select.system() ^ AvailabilityClaim("security-policy").name("Security policy is available"))

        self.release_info = self._req(
            "release-info",
            Select.software() ^ ReleaseClaim("Release history is available"))

        # Mobile applications

        self.permissions = self._req(
            "permissions",
            Select.host().type_of(HostType.MOBILE) / Select.software() ^
            PermissionClaim().name("Permissions are appropriate"))


DEFAULT = DefaultSpecification()
