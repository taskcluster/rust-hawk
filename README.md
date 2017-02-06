Hawk Authentication for Rust
============================

## TODO

* Client
  * complete HawkScheme::for_request
  * rename hawkScheme to hawk::client::Scheme, since it stutters and appears to be all the client needs
  * experiment with adding an Authorizable trait and imlementing it for RequestBuilders, so `client.get().....authorizeHawk(..).send()`

* Server
