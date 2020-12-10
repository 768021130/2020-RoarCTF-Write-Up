FROM ubuntu:20.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd python

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
COPY ./run.sh /run.sh
COPY ./qtar /home/ctf/qtar
COPY ./flag /flag

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN chmod +x /start.sh /run.sh 
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 755 /home/ctf/qtar && \
    chmod 640 /flag

CMD ["/start.sh"]

EXPOSE 8888
