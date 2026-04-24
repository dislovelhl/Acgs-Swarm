"""Compatibility facade for the remote vote transport package split."""

from constitutional_swarm.mesh import (
    ConstitutionalMesh,
    RemoteVoteReplayError,
    RemoteVoteRequest,
)
from constitutional_swarm.remote_vote_transport.peer import LocalRemotePeer
from constitutional_swarm.remote_vote_transport.protocol import (
    _LOOPBACK_HOSTS,
    RemoteVoteResponse,
    TransportSecurity,
    _build_ssl_context,
    _format_uri_host,
    _is_loopback_host,
    _parse_ws_endpoint,
    _resolve_transport_security,
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)
from constitutional_swarm.remote_vote_transport.transport import (
    RemoteVoteClient,
    RemoteVoteServer,
)

build_remote_vote_request_payload = ConstitutionalMesh.build_remote_vote_request_payload
verify_remote_vote_request = ConstitutionalMesh.verify_remote_vote_request

__all__ = [
    "_LOOPBACK_HOSTS",
    "LocalRemotePeer",
    "RemoteVoteClient",
    "RemoteVoteReplayError",
    "RemoteVoteRequest",
    "RemoteVoteResponse",
    "RemoteVoteServer",
    "TransportSecurity",
    "_build_ssl_context",
    "_format_uri_host",
    "_is_loopback_host",
    "_parse_ws_endpoint",
    "_resolve_transport_security",
    "build_remote_vote_request_payload",
    "decode_remote_vote_request",
    "decode_remote_vote_response",
    "encode_remote_vote_request",
    "encode_remote_vote_response",
    "verify_remote_vote_request",
]
