# Detect Process by Kubernetes

This documentation helps you to set up the rover in the kubernetes environment and detect kubernetes process automaticlly.

## Startup Kubernetes

Make sure that you already have a Kubernetes cluster. 

If you don't have a running cluster, you can also leverage [KinD (Kubernetes in Docker)](https://kind.sigs.k8s.io)
or [minikube](https://minikube.sigs.k8s.io) to create a cluster.

## Deploy Rover

Please following the [rover-darmonset.yml](./rover-darmonset.yml) to deploy the rover in your kubernetes cluster.
Update the comment in the file, which including two config:
1. **Rover docker image**: You could use `make docker` to build an image and upload to your private registry.
2. **OAP address**: Update the OAP address.

Then, you could use `kuberctl apply -f rover-darmonset.yml` to deploy the skywalking-rover into your cluster. 
It would deploy in each node as a DaemonSet. 