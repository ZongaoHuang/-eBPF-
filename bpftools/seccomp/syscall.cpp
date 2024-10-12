#include "agent/syscall.h"

#include <spdlog/spdlog.h>

syscall_tracker::syscall_tracker(config_data config) : tracker_with_config(config)
{
  exiting = false;
  this->current_config.env.exiting = &exiting;
}

std::unique_ptr<syscall_tracker> syscall_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "syscall_tracker";
  config.env = syscall_env{ 0 };
  return std::make_unique<syscall_tracker>(config);
}

syscall_tracker::syscall_tracker(syscall_env env)
    : syscall_tracker(config_data{
          .env = env,
      })
{
}

void syscall_tracker::start_tracker()
{
  // current_config.env.ctx = (void *)this;
  start_syscall_tracker(handle_tracker_event<syscall_tracker, syscall_event>, libbpf_print_fn, current_config.env);
}

json syscall_tracker::json_event_handler::to_json(const struct syscall_event &e)
{
  std::string res;
  json syscall = { { "type", "syscall" }, { "time", get_current_time() } };
  json syscall_event_json = json::array();

  syscall_event_json.push_back({
      { "pid", e.pid },
      { "ppid", e.ppid },
      { "syscall_id", e.syscall_id },
      { "mnt ns", e.mntns },
      { "command", e.comm },
      { "occur times", e.occur_times },
  });
  syscall.push_back({ "syscall", syscall_event_json });
  return syscall;
}

void syscall_tracker::json_event_printer::handle(tracker_event<syscall_event> &e)
{
  std::cout << to_json(e.data).dump() << std::endl;
}

void syscall_tracker::plain_text_event_printer::handle(tracker_event<syscall_event> &e)
{
  static bool is_start = true;
  if (is_start)
  {
    is_start = false;
    spdlog::info("pid\tppid\tsyscall_id\tmnt ns\tcommand\toccur time");
  }
  if (e.data.syscall_id >= syscall_names_x86_64_size) {
    return;
  }
  spdlog::info("{}\t{}\t\t{}\t\t{}\t\t{}", e.data.pid, e.data.ppid, e.data.syscall_id, e.data.comm, e.data.occur_times);
}

void syscall_tracker::prometheus_event_handler::report_prometheus_event(const struct syscall_event &e)
{
  // agent_syscall_write_counter
  //     .Add({ { "type", std::to_string(e.values[i].type) },
  //            { "filename", std::string(e.values[i].filename) },
  //            { "comm", std::string(e.values[i].comm) },
  //            { "pid", std::to_string(e.values[i].pid) } })
  //     .Increment((double)e.values[i].writes);
  // agent_syscall_read_counter
  //     .Add({
  //         { "comm", std::string(e.values[i].comm) },
  //         { "filename", std::string(e.values[i].filename) },
  //         { "pid", std::to_string(e.values[i].pid) },
  //         { "type", std::to_string(e.values[i].type) },
  //     })
  //     .Increment((double)e.values[i].reads);
  // agent_syscall_write_bytes
  //     .Add({ { "type", std::to_string(e.values[i].type) },
  //            { "filename", std::string(e.values[i].filename) },
  //            { "comm", std::string(e.values[i].comm) },
  //            { "pid", std::to_string(e.values[i].pid) } })
  //     .Increment((double)e.values[i].write_bytes);
  // agent_syscall_read_bytes
  //     .Add({
  //         { "comm", std::string(e.values[i].comm) },
  //         { "filename", std::string(e.values[i].filename) },
  //         { "pid", std::to_string(e.values[i].pid) },
  //         { "type", std::to_string(e.values[i].type) },
  //     })
  //     .Increment((double)e.values[i].read_bytes);
}

syscall_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
// : agent_syscall_read_counter(prometheus::BuildCounter()
//                                  .Name("agent_observed_syscall_read_count")
//                                  .Help("Number of observed syscall read count")
//                                  .Register(*server.registry)),
//   agent_syscall_write_counter(prometheus::BuildCounter()
//                                   .Name("agent_observed_syscall_write_count")
//                                   .Help("Number of observed syscall write count")
//                                   .Register(*server.registry)),
//   agent_syscall_write_bytes(prometheus::BuildCounter()
//                                 .Name("agent_observed_syscall_write_bytes")
//                                 .Help("Number of observed syscall write bytes")
//                                 .Register(*server.registry)),
//   agent_syscall_read_bytes(prometheus::BuildCounter()
//                                .Name("agent_observed_syscall_read_bytes")
//                                .Help("Number of observed syscall read bytes")
//                                .Register(*server.registry))
{
}

void syscall_tracker::prometheus_event_handler::handle(tracker_event<syscall_event> &e)
{
  report_prometheus_event(e.data);
}