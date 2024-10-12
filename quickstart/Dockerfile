# build run env
FROM ubuntu:22.04

ENV TZ = Asia/Shanghai

WORKDIR /usr/local/src

RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install -y net-tools
RUN apt-get install -y libelf-dev
RUN apt-get install -y curl libssl-dev libcurl4-openssl-dev libcurl4
RUN apt-get install -y wget

RUN wget https://www.gitlink.org.cn/p4zt3ZfhkI/jyedrqycjc/releases/download/v0.1/agent
RUN wget https://github.com/prometheus/prometheus/releases/download/v2.53.0/prometheus-2.53.0.linux-amd64.tar.gz
RUN tar -zxvf prometheus-2.53.0.linux-amd64.tar.gz
RUN chmod +x ./agent

EXPOSE 80
EXPOSE 8080
EXPOSE 8528
EXPOSE 9090

COPY ./ /usr/local/src

ENTRYPOINT ["/bin/bash","-l","-c"]
# ./agent server --prometheus --config test.toml && ./prometheus --config.file=./prometheus.yml && ./grafana-server --config=./defaults.ini
# mount -t debugfs none /sys/kernel/debug
# CMD ["./agent server --config test.toml"]
# CMD ["./prometheus-2.53.0.linux-amd64/prometheus --config.file=prometheus.yml --web.listen-address="0.0.0.0:9090""]
