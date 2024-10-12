#include "agent/config.h"

#include <iostream>
#include <cassert>

int main()
{
  auto config1 = agent_config_data::from_json_file("test/config.json");
  auto config2 = agent_config_data::from_toml_file("test/config.toml");

  std::cout << config1.prometheus_listening_address <<std::endl;
  std::cout << config1.enabled_trackers[0].name <<std::endl;
  std::cout << config2.prometheus_listening_address <<std::endl;
  std::cout << config1.fmt <<std::endl;
  std::cout << config2.fmt <<std::endl;
  assert(config1.fmt == config2.fmt);
  assert(config1.prometheus_listening_address == config2.prometheus_listening_address);
  assert(config1.enabled_trackers[0].name == config2.enabled_trackers[0].name);

  return 0;
}
