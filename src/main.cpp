#include <clipp.h>
#include <spdlog/spdlog.h>

#include <string>
#include <vector>

#include "agent/agent_core.h"
#include "agent/http_server.h"

using namespace std::chrono_literals;

enum class agent_mode
{
  run,
  safe,
  seccomp,
  server,
  help
};

void run_mode_operation(
    const std::string& name,
    const std::vector<std::string>& run_with_extra_args,
    agent_config_data& core_config)
{
  core_config.run_selected = "run";
  core_config.enabled_trackers.clear();
  core_config.enabled_trackers.push_back(tracker_config_data{ .name = name, .args = run_with_extra_args });
  agent_core core(core_config);
  core.start_agent();
}

void safe_mode_opertiaon(agent_config_data& core_config)
{
  core_config.run_selected = "safe";
  core_config.fmt = "none";
  core_config.enable_sec_rule_detect = true;
  agent_core core(core_config);
  core.start_agent();
}

void server_mode_operation(bool load_from_config_file, agent_config_data& core_config)
{
  if (!load_from_config_file)
  {
    core_config.fmt = "none";
    core_config.enable_sec_rule_detect = true;
  }
  std::cout << "start server mode...\n";
  core_config.run_selected = "server";
  agent_server server(core_config, 8527);
  server.serve();
}

void seccomp_mode_operation(agent_config_data& core_config)
{
  core_config.run_selected = "seccomp";
  // enable seccomp with config white list
  for (const auto& item : core_config.seccomp_data)
  {
    if (item.allow_syscall.size() >= 439)
    {
      spdlog::error("seccomp config file error : allow syscall cannot bigger than 439");
      exit(0);
    }
    else
    {
      // enable_seccomp_white_list(item);
    }
  }
}

int main(int argc, char* argv[])
{
  agent_config_data core_config;

  bool load_from_config_file = false;
  std::string config_file = "";
  agent_mode selected = agent_mode::help;
  std::string run_tracker_selected = "process";
  std::vector<std::string> run_with_extra_args;

  spdlog::set_level(spdlog::level::info);

  auto container_id_cmd =
      (clipp::option("-c", "--container") & clipp::value("container id", core_config.tracing_target_id) %
                                                    "The conatienr id of the contaienr the AGENT will monitor" >>
                                                [&core_config]() { core_config.tracing_selected = "container_id"; });
  auto process_id_cmd =
      (clipp::option("-p", "--process") & clipp::value("process id", core_config.tracing_target_id) %
                                                  "The process id of the process the AGENT will monitor" >>
                                              [&core_config]() { core_config.tracing_selected = "pid"; });
  auto run_time_cmd = (clipp::option("-T") & clipp::value("trace time in seconds", core_config.exit_after)) %
                      "The time the ENUNOMIA will monitor for";

  auto run_required_cmd = clipp::value("run required cmd name", run_tracker_selected);
  auto run_opt_cmd_args = clipp::opt_values("extra args", run_with_extra_args);

  auto config_cmd =
      (clipp::option("--config") & clipp::value("config file", config_file)) % "The toml file stores the config data";

  auto run_mode = (
      clipp::command("run").set(selected, agent_mode::run) >>
          [&core_config]() {
            core_config.enabled_export_types = { "stdout" };
            core_config.enable_container_manager = false;
          },
      run_required_cmd,
      container_id_cmd,
      run_time_cmd,
      config_cmd,
      (clipp::option("--containers").set(core_config.enable_container_manager, true)) % "Enable the container manager",
      (clipp::option("--prometheus") >> [&core_config]() { core_config.enabled_export_types.insert("prometheus"); }),
      (clipp::option("--fmt") & clipp::value("output format of the program", core_config.fmt)) %
          "The output format of AGENT, it could be \"json\", \"csv\", "
          "\"plain_txt\", and \"plain_txt\" is the default "
          "choice.",
      run_opt_cmd_args);

  auto safe_mode = (clipp::command("safe").set(selected, agent_mode::safe), config_cmd);

  auto seccomp_mode =
      (clipp::command("seccomp").set(selected, agent_mode::seccomp), process_id_cmd, run_time_cmd, config_cmd);

  auto server_cmd =
      (clipp::command("server").set(selected, agent_mode::server),
       config_cmd,
       (clipp::option("--no_safe").set(core_config.enable_sec_rule_detect, false)) % "Stop safe module",
       (clipp::option("--no_prometheus") >> [&core_config]() { core_config.enabled_export_types.erase("prometheus"); }) %
           "Stop prometheus server",
       (clipp::option("--listen") & clipp::value("listening address", core_config.prometheus_listening_address)) %
           "Listen http requests on this address, the format is like "
           "\"127.0.0.1:8528\"");

  auto cli = ((run_mode | safe_mode | seccomp_mode | server_cmd | clipp::command("help").set(selected, agent_mode::help)));

  if (!clipp::parse(argc, argv, cli))
  {
    std::cout << clipp::make_man_page(cli, argv[0]);
    return 1;
  }

  if (config_file != "")
  {
    core_config = agent_config_data::from_toml_file(config_file);
    load_from_config_file = true;
  }

  spdlog::info("agent run in cmd...");

  switch (selected)
  {
    case agent_mode::run: run_mode_operation(run_tracker_selected, run_with_extra_args, core_config); break;
    case agent_mode::safe:
      core_config.enable_sec_rule_detect = true;
      safe_mode_opertiaon(core_config);
      break;
    case agent_mode::server: server_mode_operation(load_from_config_file, core_config); break;
    case agent_mode::seccomp: seccomp_mode_operation(core_config); break;
    case agent_mode::help: std::cout << clipp::make_man_page(cli, argv[0]); break;
  }
  return 0;
}
