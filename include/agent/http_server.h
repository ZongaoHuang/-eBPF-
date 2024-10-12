#ifndef HTTP_AGENT_H
#define HTTP_AGENT_H

#include "httplib.h"
#include "agent/agent_core.h"

/// agent http control API server
class agent_server
{
private:
    /// add a mutex to serialize the http request
    std::mutex seq_mutex;
    httplib::Server server;
    agent_core core;
    int port;

public:
    /// create a server
    agent_server(agent_config_data& config, int p);
    ~agent_server() = default;
    /// start the server
    void serve(void);
};

#endif
