# Kubernetes Process Detector

The Kubernetes process detector could detect any process under the Kubernetes container.
If active the Kubernetes process detector, the rover must be deployed in the Kubernetes cluster.
After finding the process, it would collect the metadata of the process when the report to the backend.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| process_discovery.kubernetes.active | false | ROVER_PROCESS_DISCOVERY_KUBERNETES_ACTIVE | Is active the kubernetes process discovery. |
| process_discovery.kubernetes.node_name |  | ROVER_PROCESS_DISCOVERY_KUBERNETES_NODE_NAME | Current deployed node name, it could be inject by `spec.nodeName`. |
| process_discovery.kubernetes.namespaces | | ROVER_PROCESS_DISCOVERY_KUBERNETES_NAMESPACES | Including pod by namespaces, if empty means including all namespaces. Multiple namespaces split by ",". |
| process_discovery.kubernetes.analyzers | | | Declare how to build the process. The istio and k8s resources are active by default. |
| process_discovery.kubernetes.analyzers.active | | | Set is active analyzer. |
| process_discovery.kubernetes.analyzers.filters | | | Define which process is match to current process builder. |
| process_discovery.kubernetes.analyzers.service_name | | | The Service Name of the process entity. |
| process_discovery.kubernetes.analyzers.instance_name | | | The Service Instance Name of the process entity, by default, the instance name is the host IP v4 address from "en0" net interface. |
| process_discovery.kubernetes.analyzers.process_name | | | The Process Name of the process entity, by default, the process name is the executable name of the process. |
| process_discovery.kubernetes.analyzers.labels | | | The Process Labels, used to aggregate similar process from service entity. Multiple labels split by ",". |

## Process Analyze

The process analysis declares which process could be profiled and how to build the process entity.
The Istio and Kubernetes resources are active on default.

### Filter

The filter provides an expression(go template) mechanism to match the process that can build the entity. Multiple expressions work together to determine whether the process can create the entity.
Each expression must return the boolean value. Otherwise, the decision throws an error.

The context is similar to the entity builder. Using context could help the rover understand which process could build the entity.

#### Process Context

Is the same with the [process context in scanner](./scanner.md#process), but doesn't need to add the `{{` and `}}` in prefix and suffix.

#### Pod Context

Provide current pod information and judgments.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Name | None | `eq .Pod.Name "test-pod-name"` | The name of the current pod. The example shows the pod name is equal to `test-pod-name`. |
| Namespace | None | `eq .Pod.Namespace "test-namesapce"` | The name of the current pod namespace. The example shows the pod namespace name is equal to `test-namespace`. |
| Node | None | `eq .Pod.Node "test-node"` | The name of the node deployed. The example shows the pod node name is equal to `test-node`. |
| LabelValue | KeyNames | `eq .Pod.LavelValue "a,b" "v"` | The label value of the label keys, If provide multiple keys, if any key has value, then don't need to get other values. The example shows the pod has anyone `a` or `b` label key, and the value matches to `v`. |
| ServiceName | None | `eq .Pod.ServiceName "test-service"` | The service name of the pod. The example shows current pods matched service name is `test-service`. |
| HasContainer | Container name | `.Pod.HasContainer "istio-proxy"` | The pod has the appointed container name. |
| LabelSelector | selector | `.Pod.LabelSelector` | The pod is matches the label selector. For more details, please read the [official documentation](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors). |
| HasServiceName | None | `.Pod.HasServiceName` | The pod has the matched service. |

#### Container Context

Provide current container(under the pod) information.

| Name | Argument | Example | Description |
|------|--------- |-----------|-------------|
| Name | None | `eq .Container.Name "istio-proxy"`| The name of the current container under the pod. The examples show the container name is equal to `istio-proxy`. |

### Entity
The entity including `layer`, `serviceName`, `instanceName`, `processName` and `labels` properties.

The entity also could use expression to build(`serviceName`, `instanceName` and `processName`).

#### Rover

Same with the [rover context in the scanner](./scanner.md#rover).

#### Process

Same with the [process context in the scanner](./scanner.md#process).

#### Pod

The information on the current pod.

| Name | Argument |  Example  | Description |
|------|--------- |-----------|-------------|
| Name | None | `{{.Pod.Name}}` | The name of current pod. |
| Namespace | None | `{{.Pod.Namespace}}` | The name of current pod namespace. |
| Node | None | `{{.Pod.Node}}` | The name of the node deployed. |
| LabelValue | KeyNames | `{{.Pod.LavelValue "a,b"}}` | The label value of the label keys, If provide multiple keys, if any key has value, then don't need to get other values. |
| ServiceName | None | `{{.Pod.ServiceName}}` | The service name of the pod. If the pod hasn't matched service, then return an empty string. |
| FindContainer | ContainerName | `{{.Pod.FindContainer "test"}}` | Find the Container context by container name. |

#### Container

The information of the current container under the pod.

| Name | Argument | Example | Description |
|------|--------- |-----------|-------------|
| Name | None | `{{.Container.Name}}`| The name of the current container under the pod. |
| ID | None | `{{.Container.ID}}`| The id of the current container under the pod. |
| EnvValue | KeyNames | `{{.Container.EnvValue "a,b"}}`| The environment value of the keys, If provide multiple keys, if any key has value, then don't need to get other values. |