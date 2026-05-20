from .ssh_bruteforce import SSHBruteForceModule
from .owasp_web import OWASPWebModule
from .privilege_escalation import PrivEscModule
from .waf_evasion import WAFEvasionModule
from .lateral_movement import LateralMovementModule
from .ransomware_sim import RansomwareSimModule
from .credential_dumping import CredentialDumpingModule
from .data_exfiltration import DataExfiltrationModule
from .supply_chain import SupplyChainModule
from .network_load_sim import NetworkLoadSimModule
from .nmap_scan import NmapScanModule
from .apt_killchain import APTKillChainModule



MODULE_REGISTRY = {
    SSHBruteForceModule.MODULE_NAME:      SSHBruteForceModule,
    OWASPWebModule.MODULE_NAME:           OWASPWebModule,
    PrivEscModule.MODULE_NAME:            PrivEscModule,
    WAFEvasionModule.MODULE_NAME:         WAFEvasionModule,
    LateralMovementModule.MODULE_NAME:    LateralMovementModule,
    RansomwareSimModule.MODULE_NAME:      RansomwareSimModule,
    CredentialDumpingModule.MODULE_NAME:  CredentialDumpingModule,
    DataExfiltrationModule.MODULE_NAME:   DataExfiltrationModule,
    SupplyChainModule.MODULE_NAME:        SupplyChainModule,
    NetworkLoadSimModule.MODULE_NAME:     NetworkLoadSimModule,
    NmapScanModule.MODULE_NAME:           NmapScanModule,
    APTKillChainModule.MODULE_NAME: APTKillChainModule,

}
