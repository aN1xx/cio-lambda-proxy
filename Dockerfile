# Docker image that replicates AWS Lambda (Amazon Linux 2) with Python 3.9
FROM public.ecr.aws/sam/build-python3.9:1.89.0 AS base

# Install build prerequisites
RUN yum install -y zip git && yum clean all

# Install poetry and export plugin
RUN pip install --upgrade pip && \
    pip install "poetry==1.7.1" poetry-plugin-export

WORKDIR /app

# Nothing else: project will be mounted as volume at runtime 