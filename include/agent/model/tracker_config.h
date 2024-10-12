#ifndef TRACKER_CONFIG_H
#define TRACKER_CONFIG_H

#include <mutex>
#include <thread>
#include "event_handler.h"

/// the config env for a tracker
template<typename ENV>
concept env_concept = requires {
    /// is the tracker exiting?

    /// If this is true, the tracker should exit.
    typename ENV::exiting;
};

/// config data for tracker

/// pass this to create a tracker
template <typename ENV, typename EVENT>
struct tracker_config
{
    /// tracker env in C code
    ENV env;
    /// tracker name
    std::string name;
    /// event handler interface
    std::shared_ptr<event_handler<EVENT>> handler = nullptr;
};

#endif
