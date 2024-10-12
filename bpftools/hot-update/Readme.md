# a prove of concept of hot update libbpf ebpf code

```
make
make client
```

after compile, you will get a client an a server. you can simply test:

```sh
./client > update.json
sudo ./update $(cat update.json)
```

This program separated the libbpf load skeleton and exec code into 2 parts, and use json to pass the base64-encoded ebpf program between them.

the load skeleton part:

```c
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
```

the exec ebpf code part:

```c
  /* Load and verify BPF application from json*/
  struct ebpf_update_meta_data ebpf_data;
  ebpf_data.from_json_str(json_str);
  skel = single_prog_update_bpf__decode_open(ebpf_data);
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = update_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }
```

with the http RESTful API of agent, we can hot update the ebpf code using POST json to this program:

```sh
sudo ./agent server
./client 127.0.0.1:8527
```

This client will send an http request to the server and runs the ebpf bitcode on it.
