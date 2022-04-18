# Detect Process by Agent Sensor

This documentation helps you to set up service which could let rover detected automatically.

## Configure Service

Configure your service to enable the Process Status Hook feature. Take [go2sky](https://github.com/SkyAPM/go2sky) as an example here, which version must `>= v1.5.0`.

```go
// update the oap address here
r, err := reporter.NewGRPCReporter("oap-skywalking:11800", reporter.WithProcessStatusHook(true))
if err != nil {
    log.Fatalf("new reporter error %v \n", err)
}
defer r.Close()
tracer, err := go2sky.NewTracer("example", go2sky.WithReporter(r))
```

The `reporter.WithProcessStatusHook(true)` declare to enable the Process Status Hook feature.

## Starting Rover

### Enable Linux Process Scanner

After your service been startup, then configure the Linux process scanner with "AGENT_SENSOR" mode.

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
  scanner:
    period: 3s
    mode: AGENT_SENSOR
    agent:
      processStatusRefreshPeriod: 1m
```