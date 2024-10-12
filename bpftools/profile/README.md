# profile

## get nginx pid

```
cat /usr/local/openresty/nginx/logs/nginx.pid
```

```
sudo ./profile -f -F 499 -p [pid] > a.bt
```

```
cat a.bt | ~/coding/ebpf/FlameGraph/flamegraph.pl > a.svg
```

use perf

```
sudo perf script -i perf.data > out1.perf

sudo perf script -i perf.data | ~/coding/ebpf/FlameGraph/stackcollapse-perf.pl --all | ~/coding/ebpf/FlameGraph/flamegraph.pl > a.svg
```