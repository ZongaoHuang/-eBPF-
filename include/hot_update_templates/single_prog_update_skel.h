#ifndef __HOT_UPDATE_SKEL_H__
#define __HOT_UPDATE_SKEL_H__

extern "C"
{
#include <bpf/libbpf.h>
#include <stdlib.h>
}

#include "../base64.h"
#include "hot_update.h"

struct single_prog_update_bpf
{
  struct bpf_object_skeleton *skeleton;
  struct bpf_object *obj;
  struct
  {
    struct bpf_map *rb;
  } maps;
  struct
  {
    struct bpf_program *handle_exec;
  } progs;
  struct
  {
    struct bpf_link *handle_exec;
  } links;
};

static void update_bpf__destroy(struct single_prog_update_bpf *obj)
{
  if (!obj)
    return;
  if (obj->skeleton)
    bpf_object__destroy_skeleton(obj->skeleton);
  free(obj);
}

static inline int create_single_prog_skeleton_from_json(
    struct single_prog_update_bpf *obj,
    struct ebpf_update_meta_data &ebpf_data)
{
  struct bpf_object_skeleton *s;

  s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
  if (!s)
    return -1;
  obj->skeleton = s;

  s->sz = sizeof(*s);
  s->name = ebpf_data.name.c_str();
  s->obj = &obj->obj;

  /* maps */
  s->map_cnt = ebpf_data.maps_name.size();
  s->map_skel_sz = sizeof(*s->maps);
  s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
  if (!s->maps)
    goto err;

  for (int i = 0; i < s->map_cnt; i++)
  {
    s->maps[i].name = ebpf_data.maps_name[i].c_str();
    s->maps[i].map = &obj->maps.rb;
  }

  /* programs */
  s->prog_cnt = ebpf_data.progs_name.size();
  s->prog_skel_sz = sizeof(*s->progs);
  s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
  if (!s->progs)
    goto err;
  for (int i = 0; i < s->prog_cnt; i++)
  {
    s->progs[i].name = ebpf_data.progs_name[i].c_str();
    s->progs[i].prog = &obj->progs.handle_exec;
    s->progs[i].link = &obj->links.handle_exec;
  }

  s->data_sz = ebpf_data.data_sz;
  ebpf_data.base64_decode_buffer = base64_decode((const unsigned char *)ebpf_data.data.c_str(), ebpf_data.data.size());
  // s->data = ebpf_raw_data;
  s->data = (void *)ebpf_data.base64_decode_buffer.data();

  return 0;
err:
  bpf_object__destroy_skeleton(s);
  return -1;
}

static inline struct single_prog_update_bpf *single_prog_update_bpf__decode_open(struct ebpf_update_meta_data &ebpf_data)
{
  struct single_prog_update_bpf *obj;

  obj = (struct single_prog_update_bpf *)calloc(1, sizeof(*obj));
  if (!obj)
    return NULL;
  if (create_single_prog_skeleton_from_json(obj, ebpf_data))
    goto err;
  if (bpf_object__open_skeleton(obj->skeleton, NULL))
    goto err;

  return obj;
err:
  update_bpf__destroy(obj);
  return NULL;
}

static inline int update_bpf__load(struct single_prog_update_bpf *obj)
{
  return bpf_object__load_skeleton(obj->skeleton);
}

static inline int update_bpf__attach(struct single_prog_update_bpf *obj)
{
  return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void update_bpf__detach(struct single_prog_update_bpf *obj)
{
  return bpf_object__detach_skeleton(obj->skeleton);
}

#endif /* __HOT_UPDATE_SKEL_H__ */
