#ifndef TCP_CMD_H
#define TCP_CMD_H

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus/counter.h"
#include "prometheus_server.h"

extern "C"
{
#include <tcpconnect/tcp_tracker.h>
}

union sender
{
  struct in_addr x4;
  struct in6_addr x6;
};

/// ebpf tcp tracker interface
/// the true implementation is in tcp/tcp_tracker.h

/// trace tcp start and exit
class tcp_tracker : public tracker_with_config<tcp_env, tcp_event>
{
public:
  tcp_tracker(config_data config);

  /// create a tracker with deafult config
  static std::unique_ptr<tcp_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<tcp_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  // start tcp tracker
  void start_tracker();

  // used for prometheus exporter
  struct prometheus_event_handler : public event_handler<tcp_event>
  {
    prometheus::Family<prometheus::Counter> &agent_tcp_v4_counter;
    prometheus::Family<prometheus::Counter> &agent_tcp_v6_counter;
    void report_prometheus_event(tracker_event<tcp_event> &e);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tcp_event> &e);
  };
  static int fill_src_dst(sender &s, sender &d,const tcp_event &e);

  // convert event to json
  struct json_event_handler_base : public event_handler<tcp_event>
  {
    std::string to_json(const struct tcp_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler_base
  {
    void handle(tracker_event<tcp_event> &e);
  };

  struct plain_text_event_printer : public event_handler<tcp_event>
  {
    void handle(tracker_event<tcp_event> &e);
  };

  struct csv_event_printer : public event_handler<tcp_event>
  {
    void handle(tracker_event<tcp_event> &e);
  };

private:
    static void handle_tcp_sample_event(void *ctx, int cpu, void *data, unsigned int data_sz);
};

#endif
