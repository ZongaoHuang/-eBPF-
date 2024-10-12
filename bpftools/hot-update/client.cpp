extern "C"
{
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include "update.skel.h"
}

#include "update.h"
#include <fstream>

#include "../../include/httplib.h"
#include "../../include/hot_update_templates/hot_update.h"

int main(int argc, char **argv)
{
  struct update_bpf obj;
  json j;

  if (update_bpf__create_skeleton(&obj))
  {
    return 1;
  }
  if (argc < 2)
  {
    std::cout << bpf_skeleton_encode(obj.skeleton);
    return 0;
  }
  std::string harg = bpf_skeleton_encode(obj.skeleton);
  json http_data = json::parse(
      "{\
            \"name\": \"hotupdate\",\
            \"export_handlers\": [\
                {\
                    \"name\": \"plain_text\",\
                    \"args\": []\
                }\
            ],\
            \"args\": [\
            ]\
        }");
  http_data["args"].push_back(harg);
  std::cout << http_data.dump();
  httplib::Client cli(argv[1]);
  cli.Post("/start", http_data.dump(), "text/plain");

  return 0;
}
