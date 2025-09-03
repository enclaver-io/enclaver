FROM ghcr.io/astral-sh/uv:alpine3.21

WORKDIR /opt
ADD main.py pyproject.toml uv.lock /opt

RUN uv sync

ENV AWS_DEFAULT_REGION=us-east-1

ARG KMS_SYMMETRIC_KEY_ID
ENV KMS_SYMMETRIC_KEY_ID=${KMS_SYMMETRIC_KEY_ID}

ARG KMS_ASYMMETRIC_KEY_ID
ENV KMS_ASYMMETRIC_KEY_ID=${KMS_ASYMMETRIC_KEY_ID}

CMD cd /opt && uv run --frozen main.py
