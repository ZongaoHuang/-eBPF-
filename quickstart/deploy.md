# quick start depoly

sudo docker build -t agent:v0.1 .
sudo docker run agent:v0.1 

# prometheus

sudo docker pull prom/prometheus
cp ./prometheus.yml /etc/prometheus/prometheus.yml

sudo docker run -d --user root -p 9090:9090 -v /etc/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml -v /etc/prometheus/data:/data/prometheus prom/prometheus --config.file="/etc/prometheus/prometheus.yml" --web.listen-address="0.0.0.0:9090"

# grafana

sudo docker pull grafana/grafana:latest
sudo docker run -d -p 3000:3000 --name=grafana grafana/grafana:latest

# or run local


