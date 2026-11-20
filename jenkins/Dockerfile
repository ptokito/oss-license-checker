# Official Jenkins image plus Python, so pipelines can run Python scripts.
FROM jenkins/jenkins:lts

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*
USER jenkins
