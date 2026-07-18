"""FHEM-MCP – Model-Context-Protocol-Server für FHEM.

Der Server ist bewusst zustandslos bzgl. Autorisierung: das vom Client
(Claude) gesendete Bearer-Token wird bei jedem Aufruf unverändert an FHEM
durchgereicht. Über Erlaubt/Verboten entscheidet allein das FHEM-Modul
98_MCP.pm.
"""

__version__ = "0.3.0"
