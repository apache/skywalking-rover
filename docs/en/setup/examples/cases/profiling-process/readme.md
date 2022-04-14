# Profiling a Golang/C service on Linux

This documentation helps you set up the configuration to find which processes want to be monitored and profiled.

## Startup service

Startup your service in the Linux, and make sure your service already have the symbol data inside the binary file.
So we could locate the stack symbol, It could be checked following these ways:
1. **objdump**: Using `objdump --syms path/to/service`.
2. **readelf**: Using `readelf --syms path/to/service`.

## Starting Rover

### Enable Linux Process Detector

After your service been startup, then configure the Linux process detector to let Rover known how to find service.
Please make sure the Linux Process Detector have been active.

Then configure the finder to locate/identity service. It contains these data configure:
1. Regex to locate the service by command line.
2. Update the process entity builder.

#### Locate Service

You could use the `ps -ef` and `grep` to filter the which process you want to profile. In this case, my service is `sqrt`.

```shell
$ ps -ef|grep sqrt
root      2072    1790  0 14:59 pts/0    00:00:00 ./sqrt name=a
```

Follow the command example in above, you could see the last column showing the process command line is `./sqrt name=a`.
We use the regex to filter the process, In this case, we could use `sqrt` as the service identity.

#### Update Process Entity

For the demo, we update the entity data as:
1. **layer**: As the `OS_LINUX`.
2. **service**: As the `sqrt`.
3. **instance**: As local IPv4 address by network interface `en0`.
4. **process**: As the executable file name: `sqrt`.
5. **labels***: As empty.

You could be following [this configuration](../../../configuration/process_discovery/linux.md) to get more configuration information.

### Enable Profiling

Make sure the profiling module has been active.

You could be following [this configuration](../../../configuration/profiling.md) to get more configuration information.

### Full Configuration

Please follow the comment to update the backend address to your SkyWalking OAP address.

```shell
core:
  backend:
    addr: localhost:11800 # please change the backend address to your SkyWalking OAP address
    enable_TLS: false
    client_pem_path: "client.pem"
    client_key_path: "client.key"
    insecure_skip_verify: false
    ca_pem_path: "ca.pem"
    check_period: 5
    authentication: ""
    
process_discovery:
  heartbeat_period: 20s
  vm:
    active: true
    period: 3s
    finders:
      - match_cmd_regex: sqrt
        layer: OS_LINUX
        service_name: sqrt
        instance_name: {{.Rover.HostIPV4 "en0"}}
        process_name: {{.Process.ExeName}}
        labels: ""

profiling:
  active: true
  check_interval: 10s
  flush_interval: 5s
  task:
    on_cpu:
      dump_period: 9ms
```
