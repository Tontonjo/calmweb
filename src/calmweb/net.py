"""Shared HTTPS client construction for every outbound CalmWeb request.

Why this exists
---------------
OpenSSL, which Python's :mod:`ssl` module wraps, builds a certificate chain
only from what the server sends plus what is already in the local trust store.
It never fetches a missing intermediate from the ``caIssuers`` URL carried in
the leaf's Authority Information Access extension.  Windows' own verifier --
Schannel, used by curl, Edge and every native application -- does fetch it,
and caches the result in the *Intermediate Certification Authorities* store.

On a long-lived desktop that difference is invisible, because the store filled
up years ago.  On a freshly imaged machine -- a virtual machine especially,
and worse a VM rolled back on every boot -- it is empty, so any host whose
chain is not served complete fails with::

    SSLCertVerificationError: unable to get local issuer certificate

while curl, on the same machine and the same URL, succeeds.

Pinning :mod:`certifi` makes that failure *permanent* instead of fixing it:
certifi ships root certificates only, and passing ``cafile`` stops Python from
loading the Windows stores at all, so the intermediate cached by the rest of
the system is never seen either.

:mod:`truststore` is the fix.  It delegates verification to the operating
system's verifier, so CalmWeb follows exactly the same chain-building rules --
AIA fetching included -- as everything else on the machine.  It also honours a
private root deployed by an enterprise or by antivirus TLS inspection, which
matters on the networks CalmWeb is installed on.

certifi stays as a fallback for the case where truststore cannot bind to the
platform verifier: a stricter verification path is better than none.

.. versionadded:: 1.7.5
"""

from __future__ import annotations

import ssl
import threading
from typing import Any

import certifi
import urllib3

from .log import log

try:  # pragma: no cover - import guard, exercised only on unsupported setups
    import truststore
except Exception:  # noqa: BLE001 - any import failure means "fall back"
    truststore = None  # type: ignore[assignment]

#: Built once and shared: chain building is stateless and the context is
#: thread-safe, while constructing one costs a full trust-store enumeration.
_ssl_context: ssl.SSLContext | None = None
_ssl_context_lock = threading.Lock()


def _build_ssl_context() -> ssl.SSLContext:
    """Return an SSL context verifying the way the host platform does."""
    if truststore is not None:
        try:
            return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception as exc:  # noqa: BLE001 - never fail closed on startup
            log(f"truststore inutilisable ({exc}); repli sur certifi.")
    else:
        log("truststore absent; repli sur certifi.")
    return ssl.create_default_context(cafile=certifi.where())


def get_ssl_context() -> ssl.SSLContext:
    """Return the process-wide verification context, building it on first use."""
    global _ssl_context
    if _ssl_context is None:
        with _ssl_context_lock:
            if _ssl_context is None:
                _ssl_context = _build_ssl_context()
    return _ssl_context


def make_pool_manager(**kwargs: Any) -> urllib3.PoolManager:
    """Return a :class:`urllib3.PoolManager` that verifies like the OS does.

    Every outbound HTTPS request in CalmWeb goes through here, so the trust
    decision is made in exactly one place.
    """
    kwargs.setdefault("cert_reqs", "CERT_REQUIRED")
    return urllib3.PoolManager(ssl_context=get_ssl_context(), **kwargs)
