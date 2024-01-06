# Core Module

Core Module is used to communicate with the backend server.
It provides APIs for other modules to establish connections with the backend.

## Configuration

| Name                              | Default         | Environment Key                    | Description                                                                                         |
|-----------------------------------|-----------------|------------------------------------|-----------------------------------------------------------------------------------------------------|
| core.cluster_name                 |                 | ROVER_CORE_CLUSTER_NAME            | The name of the cluster.                                                                            |
| core.backend.addr                 | localhost:11800 | ROVER_BACKEND_ADDR                 | The backend server address.                                                                         |
| core.backend.enable_TLS           | false           | ROVER_BACKEND_ENABLE_TLS           | The TLS switch.                                                                                     |
| core.backend.client_pem_path      | client.pem      | ROVER_BACKEND_PEM_PATH             | The file path of client.pem. The config only works when opening the TLS switch.                     |
| core.backend.client_key_path      | client.key      | ROVER_BACKEND_KEY_PATH             | The file path of client.key. The config only works when opening the TLS switch.                     |
| core.backend.insecure_skip_verify | false           | ROVER_BACKEND_INSECURE_SKIP_VERIFY | InsecureSkipVerify controls whether a client verifies the server's certificate chain and host name. |
| core.backend.ca_pem_path          | ca.pem          | ROVER_BACKEND_CA_PEM_PATH          | The file path oca.pem. The config only works when opening the TLS switch.                           |
| core.backend.check_period         | 5               | ROVER_BACKEND_CHECK_PERIOD         | How frequently to check the connection(second).                                                     |
| core.backend.authentication       |                 | ROVER_BACKEND_AUTHENTICATION       | The auth value when send request.                                                                   |