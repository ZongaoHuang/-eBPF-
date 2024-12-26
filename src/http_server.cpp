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
void handle_start_request(const httplib::Request &req, httplib::Response &res, agent_server &server)
{
    try
    {
        spdlog::info("Accept HTTP start request");
        const std::lock_guard<std::mutex> lock(server.seq_mutex);
        nlohmann::json j = nlohmann::json::parse(req.body);
        tracker_config_data data = j.get<tracker_config_data>();
        auto id = server.core.start_tracker(data);

        std::string req_str;
        if (!id)
        {
            req_str = nlohmann::json{ {"status", "error"} }.dump();
            res.status = 400; // Bad Request
        }
        else
        {
            req_str = nlohmann::json{ {"status", "ok"}, {"id", *id} }.dump();
            res.status = 200; // OK
        }
        res.set_content(req_str, "application/json");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error in handle_start_request: {}", e.what());
        res.status = 400; // Bad Request
        res.set_content(nlohmann::json{ {"status", "error"}, {"message", e.what()} }.dump(), "application/json");
    }
}

void handle_stop_request(const httplib::Request &req, httplib::Response &res, agent_server &server)
{
    try
    {
        spdlog::info("Accept HTTP request to stop tracker");
        const std::lock_guard<std::mutex> lock(server.seq_mutex);
        nlohmann::json j = nlohmann::json::parse(req.body);
        auto id = j.at("id").get<std::size_t>();
        server.core.stop_tracker(id);
        res.status = 200; // OK
        res.set_content(nlohmann::json{ {"status", "ok"} }.dump(), "application/json");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error in handle_stop_request: {}", e.what());
        res.status = 400; // Bad Request
        res.set_content(nlohmann::json{ {"status", "error"}, {"message", e.what()} }.dump(), "application/json");
    }
}

void handle_list_request(const httplib::Request &req, httplib::Response &res, agent_server &server)
{
    try
    {
        spdlog::info("Accept HTTP request for list");
        const std::lock_guard<std::mutex> lock(server.seq_mutex);
        auto list = server.core.list_all_trackers();
        res.status = 200; // OK
        res.set_content(nlohmann::json{ {"status", "ok"}, {"list", list} }.dump(), "application/json");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error in handle_list_request: {}", e.what());
        res.status = 500; // Internal Server Error
        res.set_content(nlohmann::json{ {"status", "error"}, {"message", e.what()} }.dump(), "application/json");
    }
}

void agent_server::serve()
{
    server.Post("/start", [&](const httplib::Request &req, httplib::Response &res) {
        handle_start_request(req, res, *this);
    });

    server.Post("/stop", [&](const httplib::Request &req, httplib::Response &res) {
        handle_stop_request(req, res, *this);
    });

    server.Get("/list", [&](const httplib::Request &req, httplib::Response &res) {
        handle_list_request(req, res, *this);
    });

    core.start_agent();
    spdlog::info("Agent server start at port {}", port);
    server.listen("localhost", port);
}
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
