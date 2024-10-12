#ifndef CONTAINER_MANAGER_AGENT_H
#define CONTAINER_MANAGER_AGENT_H

#include <httplib.h>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "model/tracker.h"

extern "C"
{
#include <process/process.h>
}

/// manager all container or k8s info

/// provide a interface to get container info in handler
/// thread safe for getters and setters
class container_manager
{
 public:
  /// use process tracker to track the processes created in the container
  class container_tracking_handler : public event_handler<process_event>
  {
    container_manager &manager;

   public:
    void handle(tracker_event<process_event> &e);
    container_tracking_handler(container_manager &m) : manager(m)
    {
    }
  };

  template<typename EVENT>
      // use process tracker to track the processes created in the container
      class container_info_handler : public event_handler<EVENT>
  {
    container_manager &manager;

   public:
    void handle(tracker_event<EVENT> &e)
    {
      if (e.data.pid == 0) {
        return;
      }
      // no container info; get it
      e.ct_info = manager.get_container_info_for_pid(e.data.pid);
    }
    container_info_handler(container_manager &m) : manager(m){};
  };

  container_manager();
  // init the container info table
  void init();
  // get container info using the pid in root namespace
  container_info get_container_info_for_pid(int pid) const;

 private:
  // container client for getting container info
  class container_client
  {
   private:
    // for dockerd http api
    httplib::Client dockerd_client;

   public:
    // get all container info json string
    std::string list_all_containers(void);
    // get container process by id
    std::string list_all_process_running_in_container(const std::string &container_id);
    // get container info by id
    std::string inspect_container(const std::string &container_id);
    container_info get_os_container_info(void);
    container_client();
  };

  // for datas store in the container_info_map
  struct process_container_info_data
  {
    common_event common;
    container_info info;
  };

  // used to store container info
  // thread safe
  class container_info_map
  {
   private:
    // use rw lock to protect the map
    mutable std::shared_mutex mutex_;
    // pid -> container info
    std::unordered_map<int, process_container_info_data> container_info_map__;

   public:
    container_info_map() = default;
    // insert a container info into the map
    void insert(int pid, process_container_info_data info)
    {
      std::unique_lock<std::shared_mutex> lock(mutex_);
      container_info_map__[pid] = info;
    }
    // get a container info from the map
    std::optional<process_container_info_data> get(int pid) const
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto ct_info_p = container_info_map__.find(pid);
      if (ct_info_p != container_info_map__.end())
      {
        return ct_info_p->second;
      }
      return std::nullopt;
    }
    // remove a pid related container info from the map
    void remove(int pid)
    {
      std::unique_lock<std::shared_mutex> lock(mutex_);
      container_info_map__.erase(pid);
    }
  };

  container_info_map info_map;
  container_client client;

  // This is the default info for process not in the container
  container_info os_info;

  void get_all_process_info(void);
  // init the container info map for all running processes
  void update_container_map_data(void);
};

// helper functions
std::int64_t get_process_namespace(const char *type, int pid);
void fill_process_common_event(common_event &info, int pid);

#endif
