# findcrypto release image. GoReleaser supplies the exact prebuilt static
# binaries for each target platform; this Dockerfile never recompiles them.
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/findcrypto /usr/bin/findcrypto
COPY $TARGETPLATFORM/findbtc /usr/bin/findbtc
COPY LICENSE /usr/share/doc/findcrypto/LICENSE
COPY README.md /usr/share/doc/findcrypto/README.md
COPY CHANGELOG.md /usr/share/doc/findcrypto/CHANGELOG.md
# Raw-device scans need --privileged --user 0 (see docs/CONTAINER.md).
USER 65534:65534
ENTRYPOINT ["/usr/bin/findcrypto"]
