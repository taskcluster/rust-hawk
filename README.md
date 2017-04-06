Hawk Authentication for Rust
============================

This is a Rust implementation of (Hawk)[https://github.com/hueniverse/hawk].

## TODO

This is a work-in-progress.

* Protocol Fidelity
  * bidirectional support (server validation)
  * bewits
  * Support additional validation in the `hyper-hawk` crate:
    * nonce validation (via callback)
    * content hash validation

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`
  * adjust for clock skew

* Server
  * Send clock information on auth failure
