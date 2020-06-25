FROM gcr.io/distroless/base-debian10

COPY out/bin/pod-svid-helper /opt/bin/pod-svid-helper

ENTRYPOINT ["/opt/bin/pod-svid-helper"]
