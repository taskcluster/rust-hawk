FROM jimmycuadra/rust
MAINTAINER Dustin J. Mitchell <dustin@mozilla.com>

# instlal node in /usr/bin/
RUN apt-get update && apt-get install -y curl
RUN curl https://nodejs.org/dist/v6.11.1/node-v6.11.1-linux-x64.tar.xz | xz -d | tar -C /usr --strip=1 -xf -
