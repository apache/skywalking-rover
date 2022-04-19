# Kubernetes Process Detector

The Kubernetes process detector could detect any process under the Kubernetes container.
If active the kubernetes process detector, the rover must be deployed in the kubernetes cluster.
After find the process, it would be collect the metadata of the process when the report to the backend.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| process_discovery.kubernetes.active | false | ROVER_PROCESS_DISCOVERY_KUBERNETES_ACTIVE | Is active the kubernetes process discovery. |
| process_discovery.kubernetes.node_name |  | ROVER_PROCESS_DISCOVERY_KUBERNETES_NODE_NAME | Current deployed node name, it could be inject by `spec.nodeName`. |
| process_discovery.kubernetes.namespaces | | ROVER_PROCESS_DISCOVERY_KUBERNETES_NAMESPACES | Including pod by namespaces, if empty means including all namespaces. Multiple namespaces split by ",". |
| process_discovery.kubernetes.activated | mesh,k8s | ROVER_PROCESS_DISCOVERY_KUBERNETES_ACTIVATED | Activated process analyze feature, support "mesh", "k8s", "extend". Multiple feature split by ",". |
| process_discovery.kubernetes.cluster_name | k8s | ROVER_PROCESS_DISCOVERY_KUBERNETES_CLUSTER_NAME | Customize cluster name of the kubernetes. If active the kubernetes process analyze feature, then the cluster name as the group name. |
| process_discovery.kubernetes.mesh.service_name | {{.Pod.Namespace}}::{{.Pod.LabelValue "service.istio.io/canonical-name,app.kubernetes.io/name,app" }} | ROVER_PROCESS_DISCOVERY_KUBERNETES_MESH_SERVICE_NAME | The template to build the service name of the process under the mesh environment.|
| process_discovery.kubernetes.extend | | | Customize the process builder list. |
| process_discovery.kubernetes.extend.filters | | ROVER_PROCESS_DISCOVERY_KUBERNETES_EXTEND_FILTER | Define which process is match to current process builder. |
| process_discovery.scanner.regex.service_name | | ROVER_PROCESS_DISCOVERY_REGEX_SCANNER_SERVICE_NAME | The Service Name of the process entity. |
| process_discovery.scanner.regex.instance_name | {{pod.Name}}.{{pod.Namespace}} | ROVER_PROCESS_DISCOVERY_KUBERNETES_EXTEND_INSTANCE_NAME | The Service Instance Name of the process entity, by default, the instance name is the host IP v4 address from "en0" net interface. |
| process_discovery.scanner.regex.process_name | {{.Process.ExeName}} | ROVER_PROCESS_DISCOVERY_KUBERNETES_EXTEND_PROCESS_NAME | The Process Name of the process entity, by default, the process name is the executable name of the process. |
| process_discovery.scanner.regex.labels | | ROVER_PROCESS_DISCOVERY_KUBERNETES_EXTEND_LABELS | The Process Labels, used to aggregate similar process from service entity. Multiple labels split by ",". |

## Process Analyze

The Kubernetes process detector support three types to analyze the process:
1. **mesh**: The process under the service mesh environment.
2. **k8s**: The process under the kubernetes environment.
3. **extend**: Customize the process analyze mode.

The **mesh** and **k8s** type of the analyzer provide generic process resolution. It's similar to the extent analyze mode.

### Mesh

Analyze the processes under the service mesh pods, which contains the business service and envoy sidecar containers. 

|Layer|Filters|Service Name|Instance Name|Process Name|Process Labels|Description|
|-----|-------|------------|-------------|------------|--------------|-----------|
|MESH|`.Pod.HasContainer "istio-proxy"` and `ne .Container.Name "istio-proxy"`|config by `process_discovery.kubernetes.mesh.service_name` |`{{.Pod.Name}}`|`{{.Process.ExeName}}`|mesh-application|Business application|
|MESH_DP|`.Pod.HasContainer "istio-proxy"` and `eq .Container.Name "istio-proxy"`|config by `process_discovery.kubernetes.mesh.service_name` |`{{.Pod.Name}}`|`{{.Process.ExeName}}`|mesh-envoy|Envoy sidecar|

### K8s

Analyze all the processes in current kubernetes environment.

|Layer|Filters|Service Name|Instance Name|Process Name|Process Labels|Description|
|-----|-------|------------|-------------|------------|--------------|-----------|
|K8S_SERVICE|`.Pod.HasServiceName`|config by `process_discovery.kubernetes.cluster_name` |`{{.Pod.Name}}`|`{{.Process.ExeName}}`|k8s-service|The pod must have the matches Service selector.|

### Extend

The extent declare customize process builder, which using the filter mechanism to filter processes, and customize process entity builder.

The **mesh** and **k8s** is also use the extent mechanism, just pre-define in the rover.

#### Filter

The filter provide expression(go template) mechanism to match process that can build the entity. Multiple expressions work together to determine whether the process can create entity.
Each expression must be return the boolean value. Otherwise, the decision throws an error.

The context is similar to the entity builder. Use context could help rover understanding which process could build entity.

##### Process Context

Is same with the [process context in scanner](./scanner.md#process), but don't need to add the `{{` and `}}` in prefix and suffix. 

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| ExeFilePath | None | `{{.Process.ExeFilePath}}` | The execute file path of process. |
| ExeName | None | `{{.Process.ExeName}}` | The execute file name. |
| CommandLine | None | `{{.Process.CommandLine}}` | The command line of process. |
| Pid | None | `{{.Process.Pid}}` | The id of the process. |
| WorkDir | None | `{{.Process.WorkDir}}` | The work directory path of the process. |

##### Pod Context

Provide current pod information and judgements. 

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Name | None | `eq .Pod.Name "test-pod-name"` | The name of current pod. The example shows the pod name is equals to `test-pod-name`. |
| Namespace | None | `eq .Pod.Namespace "test-namesapce"` | The name of current pod namespace. The example shows the pod namespace name is equals to `test-namespace`. |
| Node | None | `eq .Pod.Node "test-node"` | The name of node which deployed. The example shows the pod node name is equals to `test-node`. |
| LabelValue | KeyNames | `eq .Pod.LavelValue "a,b" "v"` | The label value of the label keys, If provide multiple keys, if any key has value, then don't need to get other values. The examples shows the pod has any one `a` or `b` label key, and the value matches to `v`. |
| ServiceName | None | `eq .Pod.ServiceName "test-service"` | The service name of the pod. The example shows current pods matched service name is `test-service`. |
| HasContainer | Container name | `.Pod.HasContainer "istio-proxy"` | The pod is have the appoint container name. |
| LabelSelector | selector | `.Pod.LabelSelector` | The pod is matches the label selector. For more details, please read the [official documentation](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors). |
| HasServiceName | None | `.Pod.HasServiceName` | The pod has the matched service. |

##### Container Context

Provide current container(under the pod) information.

| Name | Argument | Example | Description |
|------|--------- |-----------|-------------|
| Name | None | `eq .Container.Name "istio-proxy"`| The name of current container under the pod. The examples shows the container name is equals to `istio-proxy`. |

#### Entity 
The entity including `layer`, `serviceName`, `instanceName`, `processName` and `labels` properties. 

The entity also could use expression to build(`serviceName`, `instanceName` and `processName`).

##### Rover

Same with the [rover context in the scanner](./scanner.md#rover).

##### Process

Same with the [process context in the scanner](./scanner.md#process).

##### Pod

The information of the current pod.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Name | None | `{{.Pod.Name}}` | The name of current pod. |
| Namespace | None | `{{.Pod.Namespace}}` | The name of current pod namespace. |
| Node | None | `{{.Pod.Node}}` | The name of node which deployed. |
| LabelValue | KeyNames | `{{.Pod.LavelValue "a,b"}}` | The label value of the label keys, If provide multiple keys, if any key has value, then don't need to get other values. |
| ServiceName | None | `{{.Pod.ServiceName}}` | The service name of the pod. If the pod haven't matched service, then return empty string. |

##### Container

The information of the current container under the pod.

| Name | Argument | Example | Description |
|------|--------- |-----------|-------------|
| Name | None | `{{.Container.Name}}`| The name of current container under the pod. |
| ID | None | `{{.Container.ID}}`| The id of current container under the pod. |