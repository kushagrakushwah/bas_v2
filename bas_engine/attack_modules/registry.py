from .ssh_bruteforce import SSHBruteForceModule
from .owasp_web import OWASPWebModule
from .privilege_escalation import PrivEscModule

# Central registry for dynamic loading based on API requests
MODULE_REGISTRY = {
    SSHBruteForceModule.MODULE_NAME: SSHBruteForceModule,
    OWASPWebModule.MODULE_NAME: OWASPWebModule,
    PrivEscModule.MODULE_NAME: PrivEscModule,
}