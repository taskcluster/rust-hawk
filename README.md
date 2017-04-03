Hawk Authentication for Rust
============================

This is a Rust implementation of [Hawk](https://github.com/hueniverse/hawk).

## TODO

This is a work-in-progress.

* Meta
  * Put request parameters in the same order everywhere (method / host / port / path)

* Protocol Fidelity
  * bidirectional support (server validation); requires
    * nonstandard "Server-Authorization" header
    * abbreviated Hawk authorization (just mac and maybe hash and/or ext) with defaults coming from request header
  * bewits
  * Support additional validation in the `hyper-hawk` crate:
    * nonce validation (via callback)
    * content hash validation

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`
  * adjust for clock skew

* Server
  * Send clock information on auth failure
