Hawk Authentication for Rust
============================

This is a Rust implementation of [Hawk](https://github.com/hueniverse/hawk).

## TODO

This is a work-in-progress.

* Protocol Fidelity
  * [DONE] bidirectional support (server validation); requires
    * [DONE] nonstandard "Server-Authorization" header
    * [DONE] abbreviated Hawk authorization (just mac and maybe hash and/or ext) with defaults coming from request header
  * [DONE] payload hash calculation
  * bewits
  * Support additional validation in the `hyper-hawk` crate:
    * nonce validation (via callback)
    * [DONE] content hash validation

* Testing
  * [DONE] req with/without hash against header with/without hash

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`
  * adjust for clock skew

* Server
  * Send clock information on auth failure

* Hyper
  * Use refs in Header once 0.11 is out

* Doc
  * Server example in hawk/src/lib.rs

* Rust
  * Fix passing around of hashes
  * allow passing more types in request building
  * use Into<Option<T>> to avoid passing Some(..)
  * use error-chain
  * use enum for Mac type
