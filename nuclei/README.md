# nuclei

Nuclei Module for Security Scanning

## Nuclei module configuration

```python
class NucleiConfig(Config):
    callback: TaskCompletionCallback
    storage_path: pathlib.Path
    name: str = "nuclei"
    docker_image: str = "projectdiscovery/nuclei:latest"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5
    templates_path: pathlib.Path = NUCLEI_TEMPLATES_PATH
```

The `storage_path` will be used to store Nuclei output files during execution.  For submitted task (see below), we save `stdout.txt.gz` and `stderr.txt.gz` from Nuclei, as well as `output.json` with the scan results.

The `templates_path` is used to store Nuclei templates.  Our goal is to minimize updating overhead for the templates every time the module is launched.  Unfortunately, the Nuclei container *always* returns that the templates are out of date, so it's unclear how much bandwidth we're currently saving.

The `name` parameter is currently only used to create a `Logger`.

## Nuclei execution

We run Nuclei using the default Docker image, mounting the credentials and output directory (as described above).  The module creates a thread to keep track of container execution, and periodically polls the Docker daemon (`NucleiConfig.docker_poll_interval`) to check if any container has finished running.  When a container has finished running, results are saved on `{NucleiConfig.storage_path}/{NucleiTask.label}`, and the callback is called.

## Testing Nuclei

* Test using Docker running `docker compose run -ti nuclei -h`
