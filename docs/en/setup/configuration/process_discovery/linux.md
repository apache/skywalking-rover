# Linux Process Detector

The Linux process detector could detect any process in the Linux with finders.
Each finder could define a regex to filter which processes declare to monitored, and the metadata of the process when the report to the backend.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| process_discovery.vm.active | false | ROVER_PROCESS_DISCOVERY_VM_ACTIVE | Is active the VM mode to detect processes. |
| process_discovery.vm.period | 3s | ROVER_PROCESS_DISCOVERY_VM_PERIOD | The period to detect the process. |
| process_discovery.vm.finders | | | It could be define multiple finders to find the process. It only provide one finder by default. |
| process_discovery.vm.finders.match_cmd_regex | | ROVER_PROCESS_DISCOVERY_VM_FINDER_MATCH_CMD_REGEX | Use regex string to locate the process from the command line of the process. |
| process_discovery.vm.finders.layer | OS_LINUX | ROVER_PROCESS_DISCOVERY_VM_FINDER_LAYER | The Layer of the process entity |
| process_discovery.vm.finders.service_name | | ROVER_PROCESS_DISCOVERY_VM_FINDER_SERVICE_NAME | The Service Name of the process entity. |
| process_discovery.vm.finders.instance_name | {{.Rover.HostIPV4 "en0"}} | ROVER_PROCESS_DISCOVERY_VM_FINDER_INSTANCE_NAME | The Service Instance Name of the process entity, by default, the instance name is the host IP v4 address from "en0" net interface. |
| process_discovery.vm.finders.process_name | {{.Process.ExeName}} | ROVER_PROCESS_DISCOVERY_VM_FINDER_PROCESS_NAME | The Process Name of the process entity, by default, the process name is the executable name of the process. |
| process_discovery.vm.finders.labels | | ROVER_PROCESS_DISCOVERY_VM_FINDER_PROCESS_LABELS | The Process Labels, used to aggregate similar process from service entity. Multiple labels split by ",". |

### Note

The duplicate processes entities cannot be reported. If multiple entities are generated, only one process will be reported.
If the multiple finders could match the same process, only the first finder could be selected and reported.

## Entity Builder

The metadata of the process could build by the Go Template to help dynamically build them, also, you could just configure it as the string value, and it still works.

These fields are supported using template to build:
1. Service Name
2. Service Instance Name
3. Process NAme

### Context

The context provides multiple functions for helping you build the process metadata.

#### Rover

Rover context provides the context of the rover process instance and VM data.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| InstanceID | None | `{{.Rover.InstanceID}}` | Get the Instance ID of the rover. |
| HostIPV4 | The Interface name | `{{.Rover.HostIPV4 "en0"}}` | Get the ipv4 address from the appointed network interface name. |
| HostIPV6 | The Interface name | `{{.Rover.HostIPV6 "en0"}}` | Get the ipv6 address from the appointed network interface name. |
| HostName | None | `{{.Rover.HostName}}` | Get the host name of current machine.|

#### Finder

Finder context provides the context of the current process finder.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Layer | None | `{{.Finder.Layer}}` | The layer of the current process which defines in the configuration | 
| RegexMatchGroup | The index of the regex pattern | `{{.Finder.RegexMatchGroup 1}}`| When using the regex to match the process command line, it could use the group concept in the regex. This function could help you get the group value from it. |

#### Process

Process context provides the context relate to which process is matched.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| ExeFilePath | None | `{{.Process.ExeFilePath}}` | The execute file path of process. |
| ExeName | None | `{{.Process.ExeName}}` | The execute file name. |
| CommandLine | None | `{{.Process.CommandLine}}` | The command line of process. |
| Pid | None | `{{.Process.Pid}}` | The id of the process. |
| WorkDir | None | `{{.Process.WorkDir}}` | The work directory path of the process. |