#ifndef AGENT_SEC_ANALYZER_H
#define AGENT_SEC_ANALYZER_H

#include "files.h"
#include "model/event_handler.h"
#include "process.h"
#include "prometheus_server.h"
#include "syscall.h"

/// sec rules info level
enum class sec_rule_level
{
  event,
  warnning,
  alert,
  // TODO: add more levels?
};

/// sec rules type

/// eg. system call, file access, etc.
enum class sec_rule_type
{
  syscall,
  tcp,
  process,
  files,
  mix,
  // TODO: add more types?
};

/// message for sec_rule

/// eg. read from file: xxx
struct rule_message
{
  sec_rule_level level;
  std::string name;
  std::string message;
  int pid;

  std::string container_id;
  std::string container_name;
};

/// describe a sec_rule
struct sec_rule_describe
{
  sec_rule_level level;
  sec_rule_type type;
  std::string name;
  std::string message;

  /// signature: the signature of the rule, for example, process name, syscall name, etc.
  std::string signature;
};

/// sec analyzer manager
class sec_analyzer
{
public:
  // EVNETODO: use the mutex
  std::mutex mutex;
  const std::vector<sec_rule_describe> rules;

  sec_analyzer(const std::vector<sec_rule_describe> &in_rules) : rules(in_rules)
  {
  }
  virtual ~sec_analyzer() = default;
  virtual void report_event(const rule_message &msg);
  void print_event(const rule_message &msg);

  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_default_rules(void);
  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_additional_rules(const std::vector<sec_rule_describe> &rules);
};

/// sec analyzer manager with prometheus exporter
class sec_analyzer_prometheus : public sec_analyzer
{
private:
  prometheus::Family<prometheus::Counter> &agent_sec_warn_counter;
  prometheus::Family<prometheus::Counter> &agent_sec_event_counter;
  prometheus::Family<prometheus::Counter> &agent_sec_alert_counter;
public:
  void report_prometheus_event(const struct rule_message &msg);
  void report_event(const rule_message &msg);
  sec_analyzer_prometheus(prometheus_server &server, const std::vector<sec_rule_describe> &rules);

  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_default_rules(prometheus_server &server);
  static std::shared_ptr<sec_analyzer> create_sec_analyzer_with_additional_rules(const std::vector<sec_rule_describe> &rules, prometheus_server &server);
};

/// base class for securiy rules detect handler
template<typename EVNET>
class rule_base :public event_handler<EVNET>
{
public:
  std::shared_ptr<sec_analyzer> analyzer;
  rule_base(std::shared_ptr<sec_analyzer> analyzer_ptr) : analyzer(analyzer_ptr) {}
  virtual ~rule_base() = default;

  // return rule id if matched
  // return -1 if not matched
  virtual int check_rule(const tracker_event<EVNET> &e, rule_message &msg) = 0;
  void handle(tracker_event<EVNET> &e)
  {
    if (!analyzer)
    {
      std::cout << "analyzer is null" << std::endl;
    }
    struct rule_message msg;
    int res = check_rule(e, msg);
    if (res != -1)
    {
      analyzer->report_event(msg);
    }
  }
};

/// files rule:

/// for example, a read or write to specific file
class files_rule_checker : public rule_base<files_event>
{
public:
  virtual ~files_rule_checker() = default;
  files_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {}
  int check_rule(const tracker_event<files_event> &e, rule_message &msg);
};

/// process rule:

/// for example, a specific process is running
class process_rule_checker : public rule_base<process_event>
{
public:
  virtual ~process_rule_checker() = default;
  process_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {}
  int check_rule(const tracker_event<process_event> &e, rule_message &msg);
};

/// syscall rule:

/// for example, a process is using a syscall
class syscall_rule_checker : public rule_base<syscall_event>
{
public:
  syscall_rule_checker(std::shared_ptr<sec_analyzer> analyzer_ptr) : rule_base(analyzer_ptr)
  {}
  int check_rule(const tracker_event<syscall_event> &e, rule_message &msg);
};

#endif