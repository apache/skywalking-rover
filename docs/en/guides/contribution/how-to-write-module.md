# How to write a new module?

If you want to add a custom module to SkyWalking Rover, the following contents would guide you.
Let's use the profiling module as an example of how to write a module.

1. Please read the [Module Design](../../concepts-and-designs/module_design.md) to understand what is module.
2. The module should be written in the **skywalking-rover/pkg** directory. So we create a new directory called profiling as the module codes space.
3. Implement the interface in the **skywalking-rover/pkg/module**. Each module has 6 methods, which are Name, RequiredModules, Config, Start, NotifyStartSuccess, and Shutdown.
    - Name returns the unique name of the module, also this name is used to define in the configuration file.
    - RequiredModules returns this needs depended on module names. In the profiling module, it needs to query the existing process and send snapshots to the backend, so it needs the core and process module.
    - Config returns the config content of this module, which relate to the configuration file, and you could declare the tag(`mapstructure`) with the field to define the name in the configuration file.
    - Start is triggered when the module needs to start. if this module start failure, please return the error.
    - NotifyStartSuccess is triggered after all the active modules are Start method success.
    - Shutdown
4. Add the configuration into the **skywalking-rover/configs/rover_configs.yaml**. It should same as the config declaration.
5. Register the module into **skywalking-rover/pkg/boot/register.go**.
6. Add the Unit test or E2E testing for testing the module is works well.
7. Write the documentation under the **skywalking-rover/docs/en** directory and add it to the documentation index file **skywalking-rover/docs/menu.yml**.