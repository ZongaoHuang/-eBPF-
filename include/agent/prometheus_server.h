#ifndef AGENT_PROMETHEUS_SERVER_H
#define AGENT_PROMETHEUS_SERVER_H

#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

#include "prometheus/exposer.h"
#include "prometheus/registry.h"
#include "model/event_handler.h"
#include "container_manager.h"

struct prometheus_server
{
    prometheus_server(std::string bind_address, container_manager& cm);
    const container_manager& core_container_manager_ref;
    prometheus::Exposer exposer;
    std::shared_ptr<prometheus::Registry> registry;
    int start_prometheus_server();
};

#endif
