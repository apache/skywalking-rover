# Linux Process Detector

The Linux process scanner could detect any process in Linux with finders. It has two modes:
1. **REGEX**: could define a regex to filter which processes declare to monitor.
2. **AGENT_SENSOR**: scan recent active agents which have process status hook.

After finding the process, it would collect the metadata of the process when the report to the backend.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| process_discovery.scanner.period | 3s | ROVER_PROCESS_DISCOVERY_SCAN_PERIOD | The period to detect the process. |
| process_discovery.scanner.mode | AGENT_SENSOR | ROVER_PROCESS_DISCOVERY_SCAN_MODE | The process detection modes of the scanner. Support "REGEX", "AGENT_SENSOR". |
| process_discovery.scanner.agent | | | Active when using the "AGENT_SENSOR" mode scanner. |
| process_discovery.scanner.agent.process_status_refresh_period | 1m | ROVER_PROCESS_DISCOVERY_AGENT_PROCESS_STATUS_REFRESH_PERIOD | Set the agent refresh period. |
| process_discovery.scanner.regex | | | Active when using the "REGEX" mode scanner, it supports using multiple regex to matches difference processes. |
| process_discovery.scanner.regex.match_cmd | | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_MATCH_CMD | Use regex string to locate the process from the command line of the process. |
| process_discovery.scanner.regex.layer | OS_LINUX | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_LAYER | The Layer of the process entity |
| process_discovery.scanner.regex.service_name | | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_SERVICE_NAME | The Service Name of the process entity. |
| process_discovery.scanner.regex.instance_name | {{.Rover.HostIPV4 "en0"}} | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_INSTANCE_NAME | The Service Instance Name of the process entity, by default, the instance name is the host IP v4 address from "en0" net interface. |
| process_discovery.scanner.regex.process_name | {{.Process.ExeName}} | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_PROCESS_NAME | The Process Name of the process entity, by default, the process name is the executable name of the process. |
| process_discovery.scanner.regex.labels | | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_LABELS | The Process Labels, used to aggregate similar process from service entity. Multiple labels split by ",". |

## Agent Sensor Mode

Agent Sensor mode scanner could scan processes that have installed the skywalking agent and report them.

### Process Status Hook File Protocol

The agent must be implemented the process status hook file protocol, then the rover could be collected the information on the process.

This protocol is mainly a metadata file, which contains the metadata of the process.
It should be saved in: `{TMPDIR}/apache_skywalking/process/{pid}/metadata.properties`, and update modify time with the interval to keep alive, the content in the `properties` format as below:

| Key | Type | Description |
|-----|------|------------|
|layer|string|this process layer.|
|service_name|string|this process service name.|
|instance_name|string|this process instance name.|
|process_name|string|this process process name, it's same with the instance name.|
|properties|json|the properties in instance, the process labels also in the properties value.|
|labels|string|the process labels, multiple labels split by ",".|
|language|string|current process language, which is `golang`.|

## Regex Mode

Regex mode scanner could define a regex to filter which process declare to monitor by command line.
Multiple regexes can be defined to match different types of processes.

Note, that the duplicate processes entities cannot be reported. If multiple entities are generated, only one process will be reported.
If the multiple finders could match the same process, only the first finder could be selected and reported.

### Entity Builder

The metadata of the process could build by the Go Template to help dynamically build them, also, you could just configure it as the string value, and it still works.

These fields are supported using the template to build:
1. Service Name
2. Service Instance Name
3. Process NAme

#### Context

The context provides multiple functions for helping you build the process metadata.

##### Rover

Rover context provides the context of the rover process instance and VM data.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| InstanceID | None | `{{.Rover.InstanceID}}` | Get the Instance ID of the rover. |
| HostIPV4 | The Interface name | `{{.Rover.HostIPV4 "en0"}}` | Get the ipv4 address from the appointed network interface name. |
| HostIPV6 | The Interface name | `{{.Rover.HostIPV6 "en0"}}` | Get the ipv6 address from the appointed network interface name. |
| HostName | None | `{{.Rover.HostName}}` | Get the host name of current machine.|

##### Finder

Finder context provides the context of the current process finder.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Layer | None | `{{.Finder.Layer}}` | The layer of the current process which defines in the configuration | 
| RegexMatchGroup | The index of the regex pattern | `{{.Finder.RegexMatchGroup 1}}`| When using the regex to match the process command line, it could use the group concept in the regex. This function could help you get the group value from it. |

##### Process

Process context provides the context relate to which process is matched.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| ExeFilePath | None | `{{.Process.ExeFilePath}}` | The execute file path of process. |
| ExeName | None | `{{.Process.ExeName}}` | The execute file name. |
| CommandLine | None | `{{.Process.CommandLine}}` | The command line of process. |
| Pid | None | `{{.Process.Pid}}` | The id of the process. |
| WorkDir | None | `{{.Process.WorkDir}}` | The work directory path of the process. |