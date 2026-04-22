#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""TLS-related tests for awscurl.

Unit tests verify SSL context configuration (no network needed).
Integration tests verify real HTTPS connections work.

Regression context (issue #235):
  On Amazon Linux 2023 the RPM ``python3-requests`` replaces the
  ``certifi`` import with a hard-coded path to the OS CA bundle
  (``/etc/pki/tls/certs/ca-bundle.crt``).  ``certifi`` is **not
  installed** — ``pip3 list`` never shows it, even after downgrading
  awscurl.  Because ``_TLSAdapter.init_poolmanager`` creates a bare
  ``ssl.SSLContext`` via ``create_urllib3_context()`` without loading
  CA certificates, HTTPS requests fail with ``SSLCertVerificationError``
  on any system where ``certifi`` is absent.
"""

from typing import Any
from unittest import TestCase
from unittest.mock import patch

from awscurl.awscurl import _TLSAdapter
from requests.adapters import HTTPAdapter

import requests


class TestTLSAdapterSSLContext(TestCase):
    """Regression test for #235: _TLSAdapter must produce an SSL context
    with system CA certificates loaded, otherwise HTTPS fails on systems
    without certifi (e.g. Amazon Linux with distro-packaged requests)."""

    def test_ssl_context_has_ca_certs(self):
        """The SSL context created by _TLSAdapter should load default certs.

        Note: we verify load_default_certs() is called rather than checking
        get_ca_certs() count, because on capath-based systems (e.g. ubuntu-22.04)
        certs aren't enumerable until an actual TLS connection uses them.
        """
        adapter = _TLSAdapter(tls_min=None, tls_max=None, verify=True)

        with patch('awscurl.awscurl.create_urllib3_context') as mock_create:
            mock_ctx = mock_create.return_value
            with patch.object(HTTPAdapter, 'init_poolmanager'):
                adapter.init_poolmanager(1, 1)

            mock_ctx.load_default_certs.assert_called_once()

    def test_ssl_context_has_ca_certs_with_tls_versions(self):
        """CA certs should also be loaded when TLS versions are specified."""
        adapter = _TLSAdapter(tls_min='1.2', tls_max='1.3', verify=True)

        with patch('awscurl.awscurl.create_urllib3_context') as mock_create:
            mock_ctx = mock_create.return_value
            with patch.object(HTTPAdapter, 'init_poolmanager'):
                adapter.init_poolmanager(1, 1)

            mock_ctx.load_default_certs.assert_called_once()


class TestHTTPSDefaultTLS(TestCase):
    """Integration test: verify real HTTPS connections work with and
    without _TLSAdapter. Any HTTP status is acceptable — we only test
    that the TLS handshake completes (SSLError would be raised otherwise)."""

    def test_https_no_ssl_error_without_tls_adapter(self):
        """Baseline: plain requests.Session completes TLS handshake."""
        with requests.Session() as session:
            response = session.get('https://awscurl-sample-bucket.s3.amazonaws.com')
        self.assertIsNotNone(response.status_code)

    def test_https_no_ssl_error_with_tls_adapter(self):
        """_TLSAdapter with explicit TLS versions completes TLS handshake."""
        with requests.Session() as session:
            session.mount('https://', _TLSAdapter(tls_min='1.2', tls_max='1.3', verify=True))
            response = session.get('https://awscurl-sample-bucket.s3.amazonaws.com')
        self.assertIsNotNone(response.status_code)

    def test_https_no_ssl_error_with_default_tls_adapter(self):
        """_TLSAdapter with no TLS args (v0.40 bug path) completes TLS handshake."""
        with requests.Session() as session:
            session.mount('https://', _TLSAdapter(tls_min=None, tls_max=None, verify=True))
            response = session.get('https://awscurl-sample-bucket.s3.amazonaws.com')
        self.assertIsNotNone(response.status_code)
