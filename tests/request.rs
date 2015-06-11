extern crate hawk;
extern crate hyper;


use hyper::Client;

/*
var credentials = {
    id: 'test-client',
    key: 'no-secret',
    algorithm: 'sha256'
}

    uri: 'http://localhost:8000/resource/1?b=1&a=2',
    method: 'GET',
Hawk.client.header('http://example.com:8000/resource/1?b=1&a=2', 'GET', { credentials: credentials, ext: 'some-app-data' });
*/

/*
#[test]
fn make_request() {

  let mut headers = hyper::header::Headers::new();
  headers.set(hyper::header::Authorization(hawk::Scheme {
    username: "test",
    password: "test2"
  }));

  let mut client = Client::new();
  let mut res = client.get("http://localhost:8000/resource")
                      .headers(headers)
                      .send().unwrap();

  println!("GET -> {}; {}", res.status, res.headers);
}
*/
