FROM ubuntu:24.04

ARG USER_UID=10001
ARG USER_GID=10001

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      bash \
      bubblewrap \
      ca-certificates \
      coreutils \
      curl \
      git \
      openssh-client \
      python3 \
      python3-pytest \
      python3-venv \
      util-linux && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -o -g "${USER_GID}" runner && \
    useradd -l -o -m -u "${USER_UID}" -g "${USER_GID}" -s /bin/bash runner && \
    mkdir -p /operator-state /home/runner/.local && \
    chown -R runner:runner /operator-state /home/runner

WORKDIR /work/operator
COPY . /work/operator
RUN chown -R runner:runner /work/operator

USER runner
ENV OPERATOR_HOME=/operator-state
ENTRYPOINT ["/work/operator/bin/operator.sh"]
CMD ["demo", "run"]
