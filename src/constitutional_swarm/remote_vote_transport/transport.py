"""Client/server runtime for remote vote exchange."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from typing import Any

from constitutional_swarm.mesh import RemoteVoteRequest
from constitutional_swarm.remote_vote_transport.protocol import (
    RemoteVoteResponse,
    TransportSecurity,
    _build_ssl_context,
    _format_uri_host,
    _parse_ws_endpoint,
    _resolve_transport_security,
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)


class RemoteVoteClient:
    """WebSocket client for one-shot remote vote requests.

    ``ssl_context`` is derived from ``transport_security`` rather than passed
    per request. ``transport_security="plaintext"`` always uses ``ws://`` with
    no SSL context, ``"tls"`` always uses ``wss://`` with an internally created
    SSL context, and ``"auto"`` derives the scheme from a ``ws://`` or
    ``wss://`` endpoint when present and otherwise defaults to plaintext for
    loopback hosts and TLS for non-loopback hosts. Passing both
    ``transport_security`` and ``ssl_context`` raises ``ValueError``.
    """

    def __init__(
        self,
        *,
        transport_security: TransportSecurity = "auto",
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if ssl_context is not None:
            raise ValueError("cannot specify both transport_security and ssl_context")
        self.transport_security = transport_security

    async def request_vote(
        self,
        host: str,
        port: int,
        request: RemoteVoteRequest,
        *,
        timeout: float = 5.0,
    ) -> RemoteVoteResponse:
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        scheme, parsed_host, parsed_port = _parse_ws_endpoint(host)
        resolved_port = parsed_port or port
        resolved_mode = _resolve_transport_security(
            transport_security=self.transport_security,
            scheme=scheme,
            host=parsed_host,
        )
        ssl_context = _build_ssl_context(resolved_mode)
        uri = f"{'wss' if resolved_mode == 'tls' else 'ws'}://{_format_uri_host(parsed_host)}:{resolved_port}"
        async with asyncio.timeout(timeout):
            async with websockets.connect(uri, ssl=ssl_context) as ws:
                await ws.send(encode_remote_vote_request(request))
                message = await ws.recv()
        return decode_remote_vote_response(str(message))


class RemoteVoteServer:
    """WebSocket server that handles one request-response remote vote RPCs.

    ``ssl_context`` is derived from ``transport_security`` rather than accepted
    separately. ``transport_security="plaintext"`` binds a ``ws://`` server with
    no SSL context, ``"tls"`` creates a server SSL context automatically, and
    ``"auto"`` derives from a ``ws://`` or ``wss://`` scheme embedded in
    ``host`` and otherwise defaults to plaintext for loopback hosts and TLS for
    non-loopback hosts. Passing both ``transport_security`` and ``ssl_context``
    raises ``ValueError``.
    """

    def __init__(
        self,
        handler: Callable[[RemoteVoteRequest], RemoteVoteResponse | Awaitable[RemoteVoteResponse]],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        transport_security: TransportSecurity = "auto",
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if ssl_context is not None:
            raise ValueError("cannot specify both transport_security and ssl_context")
        scheme, parsed_host, parsed_port = _parse_ws_endpoint(host)
        resolved_mode = _resolve_transport_security(
            transport_security=transport_security,
            scheme=scheme,
            host=parsed_host,
        )
        self._handler = handler
        self.host = parsed_host
        self.port = parsed_port or port
        self.transport_security = transport_security
        self.ssl_context = _build_ssl_context(resolved_mode, server_side=True)
        self._server: Any = None
        self._actual_port: int = self.port

    async def start(self) -> None:
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ssl=self.ssl_context,
        )
        sockets = self._server.sockets
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> RemoteVoteServer:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    @property
    def actual_port(self) -> int:
        return self._actual_port

    async def _handle_connection(self, websocket: Any) -> None:
        async for message in websocket:
            request = decode_remote_vote_request(str(message))
            response = self._handler(request)
            if asyncio.iscoroutine(response):
                response = await response
            await websocket.send(encode_remote_vote_response(response))


__all__ = ["RemoteVoteClient", "RemoteVoteServer"]
