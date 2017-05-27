Hawk Authentication for Rust
============================

This is a Rust implementation of [Hawk](https://github.com/hueniverse/hawk).

## TODO

This is a work-in-progress.

* Protocol Fidelity
  * [DONE] bidirectional support (server validation); requires
    * [DONE] nonstandard "Server-Authorization" header
    * [DONE] abbreviated Hawk authorization (just mac and maybe hash and/or ext) with defaults coming from request header
  * payload hash calculation
  * bewits
  * Support additional validation in the `hyper-hawk` crate:
    * nonce validation (via callback)
    * content hash validation

* Testing
  * req with/without hash against header with/without hash

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`
  * adjust for clock skew

* Server
  * Send clock information on auth failure
