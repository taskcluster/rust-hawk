FROM debian

# based on https://hub.docker.com/r/jimmycuadra/rust/~/dockerfile/
MAINTAINER Dustin J. Mitchell <dustin@mozilla.com>

ENV USER root

ADD setup.sh /setup.sh
RUN /bin/bash /setup.sh

ENV PATH $PATH:/root/.cargo/bin
WORKDIR /source
CMD ["/bin/bash"]
