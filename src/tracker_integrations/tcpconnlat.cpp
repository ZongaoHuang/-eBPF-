#include "agent/tracker_integrations.h"
#include "spdlog/spdlog.h"

extern "C"
{
#include "tcpconnlat/tcpconnlat_tracker.h"
}

std::unique_ptr<tcpconnlat_tracker> tcpconnlat_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "tcpconnlat";
  config.env = tracker_alone_env{ .main_func = start_tcpconnlat };
  return std::make_unique<tcpconnlat_tracker>(config);
}

tcpconnlat_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_tcpconnlat_v4_counter(prometheus::BuildHistogram()
                                        .Name("agent_observed_tcpconnlat_v4_histogram")
                                        .Help("observed tcp4 connect latency")
                                        .Register(*server.registry)),
      agent_tcpconnlat_v6_counter(prometheus::BuildHistogram()
                                        .Name("agent_observed_tcpconnlat_v6_histogram")
                                        .Help("observed tcp6 connect latency")
                                        .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void tcpconnlat_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  std::string comm;
  int pid;
  int ip;
  std::string saddr;
  std::string daddr;
  std::string port;
  std::string lat;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> pid >> comm >> ip >> saddr >> daddr >> port >> lat;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  if (ip == 4)
  {
    agent_tcpconnlat_v4_counter
        .Add(
            { { "task", comm },
              { "container_id", container_info.id },
              { "container_name", container_info.name },
              { "src", saddr },
              { "dst", daddr },
              { "port", port },
              { "pid", std::to_string(pid) } },
            prometheus::Histogram::BucketBoundaries{ 0 })
        .Observe(std::stod(lat));
  }
  else
  {
    agent_tcpconnlat_v6_counter
        .Add(
            { { "task", comm },
              { "container_id", container_info.id },
              { "container_name", container_info.name },
              { "src", saddr },
              { "dst", daddr },
              { "port", port },
              { "pid", std::to_string(pid) } },
            prometheus::Histogram::BucketBoundaries{ 0 })
        .Observe(std::stod(lat));
  }
}

std::unique_ptr<tcpconnlat_tracker> tcpconnlat_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = tcpconnlat_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
