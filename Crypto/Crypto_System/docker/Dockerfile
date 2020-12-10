FROM ubuntu:16.04

MAINTAINER callmecro

ENV REFRESHED_AT 2020-11-06

ENV LANG C.UTF-8

#请自行选择合适的端口
ENV PORT 10306

WORKDIR /

COPY sources.list /etc/apt/sources.list
COPY app /app
COPY requirements /requirements

RUN apt-get update -y
RUN apt-get install -y python python-pip libgmp-dev libmpfr-dev libmpc-dev
RUN pip install -r requirements -i https://mirrors.aliyun.com/pypi/simple/

CMD python /app/task.py

EXPOSE 10306
