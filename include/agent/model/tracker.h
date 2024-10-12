#ifndef TRAKER_H
#define TRAKER_H

#include <iostream>
#include <mutex>
#include <thread>
#include <memory>
#include <vector>

#include "tracker_config.h"
#include "spdlog/spdlog.h"

/// the base type of a tracker

/// Base class used for tracker manager to manage tracker thread
class tracker_base
{
  /// base thread
  std::jthread thread;
  /// for sync use
  std::mutex mutex;
  friend class tracker_manager;

 public:
  /// is the tracker exiting
  volatile bool exiting;
  /// constructor
  virtual ~tracker_base()
  {
    stop_tracker();
    spdlog::debug("tracker_base::~tracker_base()");
  }
  /// start the tracker thread
  virtual void start_tracker(void) = 0;
  /// stop the tracker thread
  void stop_tracker(void)
  {
    exiting = true;
    if (thread.joinable())
    {
      thread.join();
    }
  }
};

/// foward declaration for handler
class prometheus_server;

/// tracker template with env and data

/// all tracker should inherit from this class
template<typename ENV, typename EVENT>
class tracker_with_config : public tracker_base
{
public:
  /// type alias for event
  using event = EVENT;
  /// type alias for env and config
  using config_data = tracker_config<ENV, EVENT>;
  /// type alias for event handler
  using tracker_event_handler = std::shared_ptr<event_handler<EVENT>>;

  /// default event handlers for prometheus
  struct prometheus_event_handler final : public event_handler<EVENT>
  {
    prometheus_event_handler(prometheus_server &server)
    {
    }
    void handle(tracker_event<EVENT> &e)
    {
    }
  };
  /// print to plain text
  struct plain_text_event_printer final : public event_handler<EVENT>
  {
    void handle(tracker_event<EVENT> &e)
    {
    }
  };
  /// used for json exporter, inherits from json_event_handler
  struct json_event_printer final : public event_handler<EVENT>
  {
    void handle(tracker_event<EVENT> &e)
    {
    }
  };
  /// print to csv
  struct csv_event_printer final : public event_handler<EVENT>
  {
    void handle(tracker_event<EVENT> &e)
    {
    }
  };
  /// config data
  tracker_config<ENV, EVENT> current_config;
  tracker_with_config(tracker_config<ENV, EVENT> config) : current_config(config)
  {
  }

  virtual ~tracker_with_config(){
    stop_tracker();
  }
};

/// concept for a single thread tracker

/// all tracker should have these types
template<typename TRACKER>
concept tracker_concept = requires
{
  /// type alias for event
  typename TRACKER::event;
  /// type alias for config_data
  typename TRACKER::config_data;
  /// type alias for event_handler
  typename TRACKER::tracker_event_handler;
  /// prometheus_event_handler sub class
  typename TRACKER::prometheus_event_handler;
  /// json_event_handler sub class
  typename TRACKER::json_event_printer;
  /// plain_text_event_printer sub class
  typename TRACKER::plain_text_event_printer;
  /// csv_event_printer sub class
  typename TRACKER::csv_event_printer;
};

/// function for handler tracker event call back

/// used when running a tracker
/// Example:
/// start_process_tracker(handle_tracker_event<process_tracker, process_event>, libbpf_print_fn, current_config.env, skel,
/// (void *)this);
template<tracker_concept TRACKER, typename EVENT>
static int handle_tracker_event(void *ctx, void *data, size_t data_sz)
{
  if (!data || !ctx)
  {
    std::cout << "warn: no data or no ctx" << std::endl;
    return 0;
  }
  const EVENT &e = *(const EVENT *)data;
  TRACKER &pt = *(TRACKER *)ctx;
  auto event = tracker_event<EVENT>{ e };
  if (pt.current_config.handler)
  {
    pt.current_config.handler->do_handle_event(event);
  }
  else
  {
    std::cout << "warn: no handler for tracker event" << std::endl;
  }
  return 0;
}

#endif
