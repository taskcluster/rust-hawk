Hawk Authentication for Rust
============================

This is a Rust implementation of (Hawk)[https://github.com/hueniverse/hawk].

## TODO

This is a work-in-progress.

* Meta
  * Rename to hyper-hawk, or move hyper-specific bits there
  * Better error handling (custom type, `impl Error`, `impl From<io::Error>` etc.

* Client
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`

* Server
