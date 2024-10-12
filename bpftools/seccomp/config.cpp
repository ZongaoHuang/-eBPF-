#include "agent/config.h"

#include "toml.hpp"

using namespace std::string_view_literals;

void analyze_toml(std::string file_path, config& config_toml)
{
  toml::table data;
  unsigned int i, len;
  try
  {
    data = toml::parse_file(file_path);
  }
  catch (const std::exception& e)
  {
    std::cerr << e.what() << '\n';
  }
  /* fill trackers */
  len = data["trackers"]["Enable"].as_array()->size();
  for (i = 0; i < len; i++)
  {
    std::string_view tracker_name = data["trackers"]["Enable"][i].value_or(""sv);
    if (tracker_name == "syscall")
    {
      config_toml.enabled_trackers.emplace_back();
    }
    else if (tracker_name == "process")
    {
      config_toml.enabled_trackers.emplace_back(std::make_shared<process_tracker_data>(avaliable_tracker::process));
    }
    else if (tracker_name == "ipc")
    {
      config_toml.enabled_trackers.emplace_back();
    }
    else if (tracker_name == "tcp")
    {
      config_toml.enabled_trackers.emplace_back();
    }
    else if (tracker_name == "files")
    {
      config_toml.enabled_trackers.emplace_back(std::make_shared<files_tracker_data>(avaliable_tracker::files));
    }

    // trackers_config tracker_config;
    // tracker_config.tracker_name = std::string(tracker_name);
    // tracker_config.container_id = data[tracker_name]["container_id"].value_or(0);
    // tracker_config.process_id = data[tracker_name]["process_id"].value_or(0);
    // tracker_config.run_time = data[tracker_name]["run_time"].value_or(0);
    // tracker_config.fmt = data[tracker_name]["fmt"].value_or(""sv);
    // config_toml.trackers.emplace_back(tracker_config);
  }
  config_toml.target_contaienr_id = data["trackers"]["container_id"].value_or(0);
  config_toml.target_pid = data["trackers"]["process_id"].value_or(0);

  if (data["trackers"]["fmt"].value_or(""sv) == "json")
  {
    config_toml.fmt = export_format::json_format;
  }
  else if (data["trackers"]["fmt"].value_or(""sv) == "csv")
  {
    config_toml.fmt = export_format::csv;
  }
  else
  {
    config_toml.fmt = export_format::plain_text;
  }

  // /* fill rules */
  len = data["rules"]["enable"].as_array()->size();
  for (i = 0; i < len; i++)
  {
    std::string_view rule_name = data["rules"]["Enable"][i].value_or(""sv);
    rule_config rule;
    rule.rule_name = data[rule_name]["name"].value_or(""sv);
    rule.type = data[rule_name]["type"].value_or(""sv);
    rule.err_msg = data[rule_name]["error_message"].value_or(""sv);
    config_toml.rules.emplace_back(rule);
  }
  /* fill seccomp */
  len = data["seccomp"]["allow"].as_array()->size();
  for (i = 0; i < len; i++)
  {
    config_toml.seccomp.emplace_back(std::string(data["seccomp"]["allow"][i].value_or(""sv)));
  }
  // /* fill exporter */
  len = data["exporter"]["Enable"].as_array()->size();
  for (i = 0; i < len; i++)
  {
    std::string_view exporter_name = data["exporter"]["Enable"][i].value_or(""sv);
    if (exporter_name == "prometheus")
    {
      config_toml.enabled_export_types.insert(export_type::prometheus);
    }
    else if (exporter_name == "stdout_type")
    {
      config_toml.enabled_export_types.insert(export_type::stdout_type);
    }
    else if (exporter_name == "file")
    {
      config_toml.enabled_export_types.insert(export_type::file);
    }
    else if (exporter_name == "databse")
    {
      config_toml.enabled_export_types.insert(export_type::databse);
    }
  }
}