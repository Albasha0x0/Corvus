# Packages a published Linux build (the release's out folder) as the build context:
#   docker build -f Dockerfile out
# Run it with a read-only root, temporary files on tmpfs, no network and the inputs mounted read-only:
#   docker run -i --rm --read-only --tmpfs /tmp --network none -v "$PWD:/work:ro" IMAGE

# The data folder must exist in the image, owned by the app user, so a volume mounted there is writable. WORKDIR
# creates the folders without RUN, so the image builds for any platform without emulation.
FROM scratch AS folders
WORKDIR /folders/data
WORKDIR /folders/work

# Chiseled: no shell or package manager; the program runs as the non-root app user (1654).
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled@sha256:4309626281bfe550c0f6bb4242c435cd5cdabed1d05a5bc5843f659336f53296
COPY --from=folders --chown=1654:1654 /folders/ /
# Program files stay owned by root, so the app user cannot change them.
COPY --chown=0:0 . /opt/corvus/
ENV CORVUS_DATA_DIR=/data
VOLUME ["/data"]
WORKDIR /work
USER 1654
ENTRYPOINT ["/opt/corvus/corvus"]
