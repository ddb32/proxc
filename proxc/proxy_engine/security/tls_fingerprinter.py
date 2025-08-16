"""TLS Fingerprinter - TLS certificate analysis and MITM detection"""

import asyncio
import hashlib
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse

# Optional cryptography library for advanced certificate parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import aiohttp
    import aiohttp.client_exceptions
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from .security_config import SecurityConfig
from ...proxy_core.models import ProxyInfo, ProxyProtocol


@dataclass
class TLSFingerprint:
    """TLS certificate and connection fingerprint"""
    # Certificate information
    certificate_der: Optional[bytes] = None
    certificate_pem: Optional[str] = None
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    
    # Certificate fingerprints
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    md5_fingerprint: Optional[str] = None
    
    # Certificate chain
    chain_length: int = 0
    is_self_signed: bool = False
    is_ca_signed: bool = False
    
    # TLS connection details
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    
    # Extensions and features
    subject_alt_names: List[str] = field(default_factory=list)
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    
    # Security indicators
    has_weak_signature: bool = False
    has_weak_key: bool = False
    has_expired: bool = False
    has_not_yet_valid: bool = False
    
    def generate_fingerprints(self) -> None:
        """Generate certificate fingerprints from DER data"""
        if not self.certificate_der:
            return
        
        # SHA-256 fingerprint
        sha256_hash = hashlib.sha256(self.certificate_der)
        self.sha256_fingerprint = sha256_hash.hexdigest().upper()
        
        # SHA-1 fingerprint
        sha1_hash = hashlib.sha1(self.certificate_der)
        self.sha1_fingerprint = sha1_hash.hexdigest().upper()
        
        # MD5 fingerprint (for legacy compatibility)
        md5_hash = hashlib.md5(self.certificate_der)
        self.md5_fingerprint = md5_hash.hexdigest().upper()


@dataclass
class TLSAnalysisResult:
    """Result of TLS fingerprinting and analysis"""
    proxy_id: str
    is_tls_available: bool = False
    tls_fingerprint: Optional[TLSFingerprint] = None
    
    # MITM detection results
    mitm_detected: bool = False
    mitm_confidence: float = 0.0
    mitm_indicators: List[str] = field(default_factory=list)
    mitm_risk_level: str = "low"  # low, medium, high, critical
    
    # Certificate validation results
    certificate_valid: bool = False
    certificate_trusted: bool = False
    certificate_issues: List[str] = field(default_factory=list)
    
    # Security assessment
    security_score: float = 0.0  # 0-100 score
    security_grade: str = "F"    # A, B, C, D, F grading
    security_recommendations: List[str] = field(default_factory=list)
    
    # Analysis metadata
    analysis_time: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            'proxy_id': self.proxy_id,
            'is_tls_available': self.is_tls_available,
            'mitm_detected': self.mitm_detected,
            'mitm_confidence': self.mitm_confidence,
            'mitm_indicators': self.mitm_indicators,
            'mitm_risk_level': self.mitm_risk_level,
            'certificate_valid': self.certificate_valid,
            'certificate_trusted': self.certificate_trusted,
            'certificate_issues': self.certificate_issues,
            'security_score': self.security_score,
            'security_grade': self.security_grade,
            'security_recommendations': self.security_recommendations,
            'analysis_time': self.analysis_time,
            'error_message': self.error_message
        }
        
        # Add TLS fingerprint if available
        if self.tls_fingerprint:
            result['tls_fingerprint'] = {
                'subject': self.tls_fingerprint.subject,
                'issuer': self.tls_fingerprint.issuer,
                'serial_number': self.tls_fingerprint.serial_number,
                'not_before': self.tls_fingerprint.not_before.isoformat() if self.tls_fingerprint.not_before else None,
                'not_after': self.tls_fingerprint.not_after.isoformat() if self.tls_fingerprint.not_after else None,
                'sha256_fingerprint': self.tls_fingerprint.sha256_fingerprint,
                'sha1_fingerprint': self.tls_fingerprint.sha1_fingerprint,
                'chain_length': self.tls_fingerprint.chain_length,
                'is_self_signed': self.tls_fingerprint.is_self_signed,
                'protocol_version': self.tls_fingerprint.protocol_version,
                'cipher_suite': self.tls_fingerprint.cipher_suite,
                'signature_algorithm': self.tls_fingerprint.signature_algorithm,
                'subject_alt_names': self.tls_fingerprint.subject_alt_names,
                'has_weak_signature': self.tls_fingerprint.has_weak_signature,
                'has_weak_key': self.tls_fingerprint.has_weak_key,
                'has_expired': self.tls_fingerprint.has_expired,
                'has_not_yet_valid': self.tls_fingerprint.has_not_yet_valid
            }
        
        return result


class TLSFingerprinter:
    """Advanced TLS certificate analysis and MITM detection"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Known MITM signatures (common proxy/firewall certificates)
        self.known_mitm_signatures = self._load_mitm_signatures()
        
        # Weak algorithms and key sizes
        self.weak_signature_algorithms = {
            'md2', 'md4', 'md5', 'sha1'
        }
        self.weak_cipher_suites = {
            'RC4', 'DES', '3DES', 'NULL', 'EXPORT'
        }
        self.minimum_key_sizes = {
            'RSA': 2048,
            'DSA': 2048,
            'ECDSA': 256
        }
        
        self.logger.info("TLSFingerprinter initialized")
    
    def _load_mitm_signatures(self) -> Dict[str, Set[str]]:
        """Load known MITM certificate signatures"""
        return {
            # Common proxy/firewall certificate subjects
            'common_proxy_subjects': {
                'squid proxy-caching web server',
                'untrusted root ca',
                'proxy certificate',
                'mitm proxy',
                'firewall certificate'
            },
            
            # Common proxy/firewall certificate issuers
            'common_proxy_issuers': {
                'squid proxy-caching web server',
                'untrusted root ca',
                'proxy ca',
                'corporate firewall ca',
                'bluecoat',
                'fortinet',
                'sophos',
                'zscaler'
            },
            
            # Known MITM certificate fingerprints (SHA-256)
            'known_mitm_fingerprints': {
                # Add specific known MITM certificate fingerprints here
                # These would be collected from real-world analysis
            }
        }
    
    async def analyze_tls_fingerprint(self, proxy: ProxyInfo, target_host: str = "www.google.com",
                                    target_port: int = 443) -> TLSAnalysisResult:
        """Perform comprehensive TLS fingerprinting and analysis"""
        start_time = time.time()
        result = TLSAnalysisResult(proxy_id=proxy.proxy_id)
        
        try:
            # Only analyze HTTPS proxies or when TLS analysis is specifically enabled
            if proxy.protocol != ProxyProtocol.HTTPS and not getattr(self.config, 'enable_tls_analysis', False):
                result.is_tls_available = False
                result.error_message = "TLS analysis not applicable for non-HTTPS proxy"
                return result
            
            # Extract TLS certificate through proxy
            tls_fingerprint = await self._extract_tls_certificate(proxy, target_host, target_port)
            
            if not tls_fingerprint:
                result.is_tls_available = False
                result.error_message = "Failed to extract TLS certificate"
                return result
            
            result.is_tls_available = True
            result.tls_fingerprint = tls_fingerprint
            
            # Perform certificate validation
            result.certificate_valid, cert_issues = self._validate_certificate(tls_fingerprint)
            result.certificate_issues = cert_issues
            
            # Perform MITM detection
            result.mitm_detected, result.mitm_confidence, mitm_indicators = self._detect_mitm(
                tls_fingerprint, target_host
            )
            result.mitm_indicators = mitm_indicators
            
            # Determine MITM risk level
            result.mitm_risk_level = self._calculate_mitm_risk_level(result.mitm_confidence)
            
            # Calculate security score and grade
            result.security_score = self._calculate_security_score(tls_fingerprint, result)
            result.security_grade = self._calculate_security_grade(result.security_score)
            
            # Generate security recommendations
            result.security_recommendations = self._generate_security_recommendations(
                tls_fingerprint, result
            )
            
            # Check certificate trust
            result.certificate_trusted = self._is_certificate_trusted(tls_fingerprint)
            
            self.logger.debug(f"TLS analysis completed for {proxy.address}: "
                            f"valid={result.certificate_valid}, "
                            f"mitm_detected={result.mitm_detected}, "
                            f"security_grade={result.security_grade}")
            
        except Exception as e:
            result.error_message = str(e)
            self.logger.error(f"TLS analysis failed for {proxy.address}: {e}")
        
        result.analysis_time = time.time() - start_time
        return result
    
    async def _extract_tls_certificate(self, proxy: ProxyInfo, target_host: str,
                                     target_port: int) -> Optional[TLSFingerprint]:
        """Extract TLS certificate through proxy connection"""
        if not HAS_AIOHTTP:
            self.logger.warning("aiohttp not available, cannot extract TLS certificate")
            return None
        
        try:
            # Create SSL context for certificate extraction
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Configure proxy connector
            proxy_url = None
            if proxy.protocol == ProxyProtocol.HTTP:
                proxy_url = f"http://{proxy.host}:{proxy.port}"
            elif proxy.protocol == ProxyProtocol.HTTPS:
                proxy_url = f"https://{proxy.host}:{proxy.port}"
            else:
                self.logger.warning(f"Unsupported proxy protocol for TLS analysis: {proxy.protocol}")
                return None
            
            connector = aiohttp.connector.ProxyConnector.from_url(proxy_url)
            
            timeout = aiohttp.ClientTimeout(
                total=getattr(self.config, 'tls_analysis_timeout', 10.0)
            )
            
            # Connect through proxy and extract certificate
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                
                # Make HTTPS request to target through proxy
                target_url = f"https://{target_host}:{target_port}/"
                
                async with session.get(target_url) as response:
                    # Get SSL information from the connection
                    if hasattr(response.connection, 'transport') and \
                       hasattr(response.connection.transport, 'get_extra_info'):
                        
                        ssl_object = response.connection.transport.get_extra_info('ssl_object')
                        if ssl_object:
                            return await self._parse_ssl_certificate(ssl_object, target_host)
                    
                    # Fallback: direct SSL connection to extract certificate
                    return await self._direct_ssl_extraction(target_host, target_port)
        
        except Exception as e:
            self.logger.debug(f"TLS certificate extraction failed: {e}")
            return None
    
    async def _direct_ssl_extraction(self, host: str, port: int) -> Optional[TLSFingerprint]:
        """Direct SSL connection to extract certificate (fallback method)"""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=host) as ssock:
                    return await self._parse_ssl_certificate(ssock, host)
        
        except Exception as e:
            self.logger.debug(f"Direct SSL extraction failed for {host}:{port}: {e}")
            return None
    
    async def _parse_ssl_certificate(self, ssl_object, hostname: str) -> Optional[TLSFingerprint]:
        """Parse SSL certificate from SSL object"""
        try:
            # Get certificate in DER format
            cert_der = ssl_object.getpeercert(binary_form=True)
            if not cert_der:
                return None
            
            # Get certificate in text format
            cert_dict = ssl_object.getpeercert(binary_form=False)
            if not cert_dict:
                return None
            
            fingerprint = TLSFingerprint()
            fingerprint.certificate_der = cert_der
            
            # Generate fingerprints
            fingerprint.generate_fingerprints()
            
            # Parse basic certificate information
            fingerprint.subject = dict(x[0] for x in cert_dict.get('subject', []))
            fingerprint.issuer = dict(x[0] for x in cert_dict.get('issuer', []))
            fingerprint.serial_number = str(cert_dict.get('serialNumber', ''))
            
            # Parse dates
            not_before_str = cert_dict.get('notBefore')
            if not_before_str:
                fingerprint.not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
            
            not_after_str = cert_dict.get('notAfter')
            if not_after_str:
                fingerprint.not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            
            # Check validity dates
            now = datetime.now()
            if fingerprint.not_after and now > fingerprint.not_after:
                fingerprint.has_expired = True
            if fingerprint.not_before and now < fingerprint.not_before:
                fingerprint.has_not_yet_valid = True
            
            # Parse Subject Alternative Names
            san_extension = cert_dict.get('subjectAltName', [])
            fingerprint.subject_alt_names = [name[1] for name in san_extension if name[0] == 'DNS']
            
            # Get TLS connection information
            fingerprint.protocol_version = ssl_object.version()
            fingerprint.cipher_suite = ssl_object.cipher()[0] if ssl_object.cipher() else None
            
            # Check for self-signed certificate
            fingerprint.is_self_signed = fingerprint.subject == fingerprint.issuer
            fingerprint.is_ca_signed = not fingerprint.is_self_signed
            
            # Advanced parsing with cryptography library
            if HAS_CRYPTOGRAPHY:
                await self._parse_with_cryptography(fingerprint, cert_der)
            
            # Analyze certificate security
            await self._analyze_certificate_security(fingerprint)
            
            return fingerprint
        
        except Exception as e:
            self.logger.debug(f"Certificate parsing failed: {e}")
            return None
    
    async def _parse_with_cryptography(self, fingerprint: TLSFingerprint, cert_der: bytes):
        """Enhanced certificate parsing using cryptography library"""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Get signature algorithm
            fingerprint.signature_algorithm = cert.signature_algorithm_oid._name
            
            # Get public key information
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                fingerprint.key_size = public_key.key_size
            
            # Parse extensions
            try:
                key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                fingerprint.key_usage = [usage for usage in [
                    'digital_signature', 'content_commitment', 'key_encipherment',
                    'data_encipherment', 'key_agreement', 'key_cert_sign',
                    'crl_sign', 'encipher_only', 'decipher_only'
                ] if getattr(key_usage_ext.value, usage, False)]
            except x509.ExtensionNotFound:
                pass
            
            try:
                eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                fingerprint.extended_key_usage = [oid._name for oid in eku_ext.value]
            except x509.ExtensionNotFound:
                pass
            
        except Exception as e:
            self.logger.debug(f"Advanced certificate parsing failed: {e}")
    
    async def _analyze_certificate_security(self, fingerprint: TLSFingerprint):
        """Analyze certificate for security weaknesses"""
        # Check for weak signature algorithms
        if fingerprint.signature_algorithm:
            sig_alg_lower = fingerprint.signature_algorithm.lower()
            for weak_alg in self.weak_signature_algorithms:
                if weak_alg in sig_alg_lower:
                    fingerprint.has_weak_signature = True
                    break
        
        # Check for weak key sizes
        if fingerprint.key_size:
            # Determine key type from signature algorithm
            key_type = None
            if fingerprint.signature_algorithm:
                if 'rsa' in fingerprint.signature_algorithm.lower():
                    key_type = 'RSA'
                elif 'dsa' in fingerprint.signature_algorithm.lower():
                    key_type = 'DSA'
                elif 'ecdsa' in fingerprint.signature_algorithm.lower():
                    key_type = 'ECDSA'
            
            if key_type and key_type in self.minimum_key_sizes:
                if fingerprint.key_size < self.minimum_key_sizes[key_type]:
                    fingerprint.has_weak_key = True
    
    def _validate_certificate(self, fingerprint: TLSFingerprint) -> Tuple[bool, List[str]]:
        """Validate certificate and return issues"""
        issues = []
        
        # Check expiration
        if fingerprint.has_expired:
            issues.append("Certificate has expired")
        
        if fingerprint.has_not_yet_valid:
            issues.append("Certificate is not yet valid")
        
        # Check for weak cryptography
        if fingerprint.has_weak_signature:
            issues.append("Certificate uses weak signature algorithm")
        
        if fingerprint.has_weak_key:
            issues.append("Certificate uses weak key size")
        
        # Check for self-signed certificates
        if fingerprint.is_self_signed:
            issues.append("Certificate is self-signed")
        
        # Certificate is valid if no critical issues
        is_valid = len(issues) == 0 or (len(issues) == 1 and "self-signed" in issues[0])
        
        return is_valid, issues
    
    def _detect_mitm(self, fingerprint: TLSFingerprint, expected_host: str) -> Tuple[bool, float, List[str]]:
        """Detect potential MITM attacks"""
        indicators = []
        confidence = 0.0
        
        # Check against known MITM signatures
        subject_cn = fingerprint.subject.get('commonName', '').lower()
        issuer_cn = fingerprint.issuer.get('commonName', '').lower()
        
        # Check for proxy/firewall certificate subjects
        for proxy_subject in self.known_mitm_signatures['common_proxy_subjects']:
            if proxy_subject in subject_cn:
                indicators.append(f"Certificate subject indicates proxy: {subject_cn}")
                confidence += 0.4
        
        # Check for proxy/firewall certificate issuers
        for proxy_issuer in self.known_mitm_signatures['common_proxy_issuers']:
            if proxy_issuer in issuer_cn:
                indicators.append(f"Certificate issuer indicates proxy: {issuer_cn}")
                confidence += 0.3
        
        # Check for certificate fingerprint matches
        if fingerprint.sha256_fingerprint in self.known_mitm_signatures['known_mitm_fingerprints']:
            indicators.append("Certificate fingerprint matches known MITM certificate")
            confidence += 0.8
        
        # Check for hostname mismatch
        if not self._hostname_matches_certificate(expected_host, fingerprint):
            indicators.append(f"Certificate does not match expected hostname: {expected_host}")
            confidence += 0.2
        
        # Check for suspicious certificate properties
        if fingerprint.is_self_signed:
            indicators.append("Certificate is self-signed")
            confidence += 0.3
        
        # Check for generic/suspicious subject names
        if subject_cn in ['localhost', 'proxy', 'firewall', 'gateway']:
            indicators.append(f"Certificate has suspicious subject name: {subject_cn}")
            confidence += 0.2
        
        # Confidence should not exceed 1.0
        confidence = min(1.0, confidence)
        
        # MITM is detected if confidence is above threshold
        mitm_detected = confidence >= 0.5
        
        return mitm_detected, confidence, indicators
    
    def _hostname_matches_certificate(self, hostname: str, fingerprint: TLSFingerprint) -> bool:
        """Check if hostname matches certificate"""
        # Check common name
        cert_cn = fingerprint.subject.get('commonName', '')
        if cert_cn == hostname:
            return True
        
        # Check Subject Alternative Names
        for san in fingerprint.subject_alt_names:
            if san == hostname:
                return True
            # Support wildcard matching
            if san.startswith('*.'):
                domain = san[2:]
                if hostname.endswith('.' + domain):
                    return True
        
        return False
    
    def _calculate_mitm_risk_level(self, confidence: float) -> str:
        """Calculate MITM risk level based on confidence"""
        if confidence >= 0.8:
            return "critical"
        elif confidence >= 0.6:
            return "high"
        elif confidence >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _calculate_security_score(self, fingerprint: TLSFingerprint, result: TLSAnalysisResult) -> float:
        """Calculate overall security score (0-100)"""
        score = 100.0
        
        # Deduct for certificate issues
        if fingerprint.has_expired:
            score -= 30
        if fingerprint.has_not_yet_valid:
            score -= 20
        if fingerprint.has_weak_signature:
            score -= 25
        if fingerprint.has_weak_key:
            score -= 20
        if fingerprint.is_self_signed:
            score -= 15
        
        # Deduct for MITM detection
        if result.mitm_detected:
            score -= result.mitm_confidence * 40  # Up to 40 points deduction
        
        # Bonus for good practices
        if fingerprint.key_size and fingerprint.key_size >= 2048:
            score += 5
        if len(fingerprint.subject_alt_names) > 0:
            score += 5
        
        return max(0.0, min(100.0, score))
    
    def _calculate_security_grade(self, score: float) -> str:
        """Calculate security grade from score"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _is_certificate_trusted(self, fingerprint: TLSFingerprint) -> bool:
        """Determine if certificate is trusted"""
        # Basic trust assessment
        if fingerprint.is_self_signed:
            return False
        if fingerprint.has_expired or fingerprint.has_not_yet_valid:
            return False
        if fingerprint.has_weak_signature or fingerprint.has_weak_key:
            return False
        
        return True
    
    def _generate_security_recommendations(self, fingerprint: TLSFingerprint,
                                         result: TLSAnalysisResult) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if fingerprint.has_expired:
            recommendations.append("Certificate has expired - avoid using this proxy")
        
        if fingerprint.has_weak_signature:
            recommendations.append("Certificate uses weak signature algorithm - consider security risks")
        
        if fingerprint.has_weak_key:
            recommendations.append("Certificate uses weak key size - may be vulnerable to attacks")
        
        if fingerprint.is_self_signed:
            recommendations.append("Self-signed certificate detected - verify proxy legitimacy")
        
        if result.mitm_detected:
            recommendations.append("Potential MITM attack detected - use with extreme caution")
        
        if result.security_score < 70:
            recommendations.append("Poor security score - consider using a different proxy")
        
        return recommendations


# Convenience functions

async def analyze_proxy_tls(proxy: ProxyInfo, target_host: str = "www.google.com",
                           config: Optional[SecurityConfig] = None) -> TLSAnalysisResult:
    """Convenience function for TLS analysis"""
    fingerprinter = TLSFingerprinter(config)
    return await fingerprinter.analyze_tls_fingerprint(proxy, target_host)


def quick_tls_check(proxy: ProxyInfo) -> bool:
    """Quick check if proxy supports TLS analysis"""
    return proxy.protocol in [ProxyProtocol.HTTPS] or HAS_AIOHTTP