# Setting Override
SkyWalking Rover supports setting overrides by system environment variables. 
You could override the settings in `rover_configs.yaml`

## System environment variables
- Example

  Override `core.backend.addr` in this setting segment through environment variables
  
```yaml
core:
  backend: 
    addr: ${ROVER_BACKEND_ADDR:localhost:11800}
```

If the `ROVER_BACKEND_ADDR ` environment variable exists in your operating system and its value is `oap:11800`, 
then the value of `core.backend.addr` here will be overwritten to `oap:11800`, otherwise, it will be set to `localhost:11800`.