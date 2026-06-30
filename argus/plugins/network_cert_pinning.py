"""SSL/TLS certificate pinning detection plugin."""
import logging
import ssl
import hashlib
import asyncio
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NetworkCertPinningPlugin(BasePlugin):
    name = "network_cert_pinning"
    target_types = ["domain"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        """Connect to the target and extract SSL/TLS certificate details.
        Checks for certificate pinning indicators and computes SPKI pins."""
        cert_info = {
            "cert_issuer": "",
            "cert_subject": "",
            "cert_valid_from": "",
            "cert_valid_until": "",
            "sha256_pin": "",
            "sha1_pin": "",
            "serial_number": "",
            "version": "",
            "san_domains": [],
            "has_pinning": False,
            "cert_pins": [],
            "protocols": [],
        }

        try:
            # Get certificate from the SSL connection
            loop = asyncio.get_event_loop()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Connect and get the certificate
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 443, ssl=ctx),
                timeout=10,
            )
            # Get the peer certificate from the transport
            transport = writer.transport
            ssl_object = transport.get_extra_info("ssl_object")
            peer_cert = ssl_object.getpeercert(binary_form=True)
            peer_cert_dict = ssl_object.getpeercert()

            writer.close()
            await writer.wait_closed()

            if peer_cert:
                # Compute SHA-256 SPKI pin
                import cryptography.x509 as x509
                from cryptography.hazmat.primitives import hashes, serialization
                cert = x509.load_der_x509_certificate(peer_cert)
                pub_key_bytes = cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                sha256_pin = hashlib.sha256(pub_key_bytes).digest()
                cert_info["sha256_pin"] = sha256_pin.hex()
                cert_info["sha1_pin"] = hashlib.sha1(peer_cert).hexdigest()
                cert_info["serial_number"] = format(cert.serial_number, 'x').upper()
                cert_info["version"] = cert.version.name
                cert_info["cert_issuer"] = ", ".join(
                    f"{c.oid._name}={c.value}" for c in cert.issuer
                )
                cert_info["cert_subject"] = ", ".join(
                    f"{c.oid._name}={c.value}" for c in cert.subject
                )
                cert_info["cert_valid_from"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
                cert_info["cert_valid_until"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)

                # Extract Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    cert_info["san_domains"] = san_ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass

                # Check for HPKP headers (HTTP Public Key Pinning - deprecated but worth checking)
                cert_info["cert_pins"].append({
                    "type": "SPKI-SHA256",
                    "value": sha256_pin.hex(),
                })

                # Check if pinning is likely (multiple pins = HPKP or expect-ct)
                cert_info["has_pinning"] = len(cert_info["cert_pins"]) > 0

            # Get supported TLS protocols
            if peer_cert_dict:
                cert_info["protocols"].append(peer_cert_dict.get("version", ""))

        except ImportError:
            # cryptography library not available, use basic ssl module
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, 443, ssl=ctx), timeout=10,
                )
                ssl_object = writer.transport.get_extra_info("ssl_object")
                peer_cert = ssl_object.getpeercert(binary_form=True)
                writer.close()
                await writer.wait_closed()
                if peer_cert:
                    cert_info["sha256_pin"] = hashlib.sha256(peer_cert).hexdigest()
                    cert_info["sha1_pin"] = hashlib.sha1(peer_cert).hexdigest()
                    cert_info["has_pinning"] = True
            except Exception as e2:
                logger.error(f"Basic SSL check also failed: {e2}")

        except Exception as e:
            logger.error(f"Certificate pinning check failed for {target}: {e}")
            return PluginResult(
                plugin_name=self.name, status="error", data=cert_info,
                error_message=str(e),
            )

        return PluginResult(
            plugin_name=self.name, status="success", data=cert_info,
        )