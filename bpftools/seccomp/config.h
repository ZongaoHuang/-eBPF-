#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H

#include <chrono>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "files.h"
#include "ipc.h"
#include "model/tracker_config.h"
#include "process.h"
#include "tcp.h"

// export config
enum class export_format
{
  json_format,
  csv,
  plain_text
};

enum class export_type
{
  prometheus,
  stdout_type,
  file,
  databse
};

enum class agent_mode
{
  run,
  daemon,
  seccomp,
  server,
  help
};

enum class tracing_type
{
  pid,
  container_id,
  all
};

// all available tracker
enum class avaliable_tracker
{
  syscall,
  process,
  ipc,
  tcp,
  files
};

// TODO refactor
// we should not use enum class
// use dynamic_cast to get the type of tracker
struct tracker_data_base
{
  avaliable_tracker type;
};

// tracker config data template
template<typename T>
struct tracker_data : tracker_data_base
{
  T config;
  tracker_data(avaliable_tracker t) : tracker_data_base{t} {}
};

using process_tracker_data = tracker_data<process_tracker::config_data>;
using files_tracker_data = tracker_data<files_tracker::config_data>;

struct rule_config 
{
    std::string rule_name;
    std::string type;
    std::string trigger;
    std::string err_msg;
};

// config for agent
// both config from toml and command line should be put here
struct config
{
  // global run mode
  agent_mode run_selected = agent_mode::server;

  // config for all enabled tracker
  // each tracker should have its own config, for example, process_tracker_data
  // you can add fields to config_data, just replace the using with struct decleration
  // see:
  // using config_data = tracker_config<process_env, process_event>;
  std::vector<std::shared_ptr<tracker_data_base>> enabled_trackers = {
        std::make_shared<process_tracker_data>(avaliable_tracker::process),
        std::make_shared<files_tracker_data>(avaliable_tracker::files),
  };

  // export config
  // may be we should have config similar to tracker_config
  // TODO
  std::set<export_type> enabled_export_types = {export_type::prometheus, export_type::stdout_type};

  // export format
  // this should be set as well
  // TODO
  export_format fmt = export_format::plain_text;

  // enable container tracing
  // we can get container id and container name
  // using pid from the map of it
  bool enable_container_manager = false;

  // tracing config
  tracing_type tracing_selected = tracing_type::all;
  // tracing targets
  // std::string container_name = "";
  unsigned long target_contaienr_id = 0;
  pid_t target_pid = 0;

  bool is_auto_exit = false;
  int exit_after = 0;

  // TODO: this should be add to export config
  std::string prometheus_listening_address = "127.0.0.1:8528";

  std::vector<rule_config> rules;
  std::vector<std::string> seccomp;
};

struct seccomp_config {
  // the length of banned syscalls
  int len = 0;
  // the syscalls name which is allowed
  std::string allow_syscall[439];
};

static void analyze_toml(std::string file_path, config &config_toml);
#endif
