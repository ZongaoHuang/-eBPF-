#include "agent/http_server.h"

#include <spdlog/spdlog.h>

#include <json.hpp>

#include "agent/config.h"

#define get_from_json_at(name)                   \
  try                                            \
  {                                              \
    j.at(#name).get_to(data.name);               \
  }                                              \
  catch (...)                                    \
  {                                              \
    spdlog::warn("{} use default value", #name); \
  }

static void from_json(const nlohmann::json &j, handler_config_data &data)
{
  get_from_json_at(name);
  get_from_json_at(args);
}

static void from_json(const nlohmann::json &j, tracker_config_data &data)
{
  get_from_json_at(name);
  get_from_json_at(args);
  get_from_json_at(export_handlers);
}

agent_server::agent_server(agent_config_data &config, int p) : core(config), port(p)
{
}

void agent_server::serve()
{
  server.Post("/start", [=](const httplib::Request &req, httplib::Response &res) {
    spdlog::info("accept http start request");
    const std::lock_guard<std::mutex> lock(seq_mutex);
    std::string req_str;
    tracker_config_data data;
    try
    {
      nlohmann::json j = nlohmann::json::parse(req.body);
      data = j.get<tracker_config_data>();
      auto id = core.start_tracker(data);
      if (!id)
      {
        req_str = nlohmann::json{ "status", "error" }.dump();
      }
      else
      {
        req_str = nlohmann::json{ "status", "ok", "id", *id }.dump();
      }
    }
    catch (...)
    {
      spdlog::error("json parse error for tracker_config_data! {}", req.body);
      res.status = 404;
      return;
    }
    res.status = 200;
    res.set_content(req_str, "text/plain");
  });

  server.Post("/stop", [=](const httplib::Request &req, httplib::Response &res) {
    spdlog::info("accept http request to stop tracker");
    const std::lock_guard<std::mutex> lock(seq_mutex);
    std::string req_str;
    try
    {
      nlohmann::json j = nlohmann::json::parse(req.body);
      auto id = j.at("id").get<std::size_t>();
      core.stop_tracker(id);
      req_str = nlohmann::json{ "status", "ok" }.dump();
    }
    catch (...)
    {
      spdlog::error("json parse error for stop tracker {}", req.body);
      res.status = 404;
      return;
    }
    res.status = 200;
    res.set_content(req_str, "text/plain");
  });

  server.Get("/list", [=](const httplib::Request &req, httplib::Response &res) {
    spdlog::info("accept http request for list");
    const std::lock_guard<std::mutex> lock(seq_mutex);
    std::string req_str;
    try
    {
      auto list = core.list_all_trackers();
      req_str = nlohmann::json{ "status", "ok", "list", list }.dump();
    }
    catch (...)
    {
      spdlog::error("json parse error for list trackers {}", req.body);
      res.status = 404;
      return;
    }
    res.status = 200;
    res.set_content(req_str, "text/plain");
  });
  core.start_agent();
  spdlog::info("agent server start at port {}", port);
  server.listen("localhost", port);
}
