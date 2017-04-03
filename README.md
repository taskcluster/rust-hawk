Hawk Authentication for Rust
============================

This is a Rust implementation of (Hawk)[https://github.com/hueniverse/hawk].

## TODO

This is a work-in-progress.

* Protocol Fidelity
  * Support additional validation in the `hawk` crate:
    * timestamp skew
    * nonce validation (via callback)
    * content hash validation
* Meta
  * Better error handling (custom type, `impl Error`, `impl From<io::Error>` etc.
  * Put request parameters in the same order everywhere (method / host / port / path)

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`
  * adjust for clock skew
  * Bewits

* Server
  * Send clock information on auth failure
  * Bewits
