FROM k8s.gcr.io/debian-base-amd64:v2.0.0

RUN /usr/local/bin/clean-install curl git ca-certificates openssl

COPY out/bin/pod-svid-helper /opt/bin/pod-svid-helper

ENTRYPOINT ["/opt/bin/pod-svid-helper"]
