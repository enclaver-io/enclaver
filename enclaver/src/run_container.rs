use anyhow::{anyhow, Result};
use bollard::container::LogOutput;
use bollard::models::{ContainerCreateBody, DeviceMapping, HostConfig, PortBinding, PortMap};
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions, WaitContainerOptions,
};
use bollard::Docker;
use futures_util::stream::{StreamExt, TryStreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct Sleeve {
    docker: Arc<Docker>,
    container_id: Option<String>,
    stream_task: Option<tokio::task::JoinHandle<()>>,
}

impl Sleeve {
    pub fn new() -> Result<Self> {
        let docker_client = Arc::new(
            Docker::connect_with_local_defaults()
                .map_err(|e| anyhow!("connecting to docker: {}", e))?,
        );

        Ok(Self {
            docker: docker_client,
            container_id: None,
            stream_task: None,
        })
    }

    pub async fn run_enclaver_image(
        &mut self,
        image_name: &str,
        port_forwards: Vec<String>,
        debug_mode: bool,
    ) -> Result<()> {
        if self.container_id.is_some() {
            return Err(anyhow!("container already running"));
        }

        let port_re = regex::Regex::new(r"(\d+):(\d+)")?;

        let mut exposed_ports: HashMap<String, HashMap<(), ()>> = HashMap::new();
        let mut port_bindings = PortMap::new();

        for spec in port_forwards {
            let captures = port_re.captures(&spec).ok_or_else(|| {
                anyhow!(
                    "port forward specification '{spec}' does not match the format 'host_port:container_port'",
                )
            })?;
            let host_port = captures.get(1).unwrap().as_str();
            let container_port = captures.get(2).unwrap().as_str();
            exposed_ports.insert(format!("{container_port}/tcp"), HashMap::new());

            port_bindings.insert(
                format!("{container_port}/tcp"),
                Some(vec![PortBinding {
                    host_port: Some(host_port.to_string()),
                    host_ip: None,
                }]),
            );
        }

        let container_id = self
            .docker
            .create_container(
                None::<CreateContainerOptions>,
                ContainerCreateBody {
                    image: Some(image_name.to_string()),
                    cmd: match debug_mode {
                        // TODO(russell_h): pass through additional args
                        true => Some(vec!["--debug-mode".into()]),
                        false => None,
                    },
                    attach_stderr: Some(true),
                    attach_stdout: Some(true),
                    host_config: Some(HostConfig {
                        devices: Some(vec![DeviceMapping {
                            path_on_host: Some(String::from("/dev/nitro_enclaves")),
                            path_in_container: Some(String::from("/dev/nitro_enclaves")),
                            cgroup_permissions: Some(String::from("rwm")),
                        }]),
                        port_bindings: Some(port_bindings),
                        privileged: Some(true),
                        ..Default::default()
                    }),
                    exposed_ports: Some(exposed_ports),
                    ..Default::default()
                },
            )
            .await?
            .id;

        self.container_id = Some(container_id.clone());

        self.docker
            .start_container(&container_id, None::<StartContainerOptions>)
            .await?;

        self.start_output_stream_task(container_id.clone()).await?;

        let status_code = self
            .docker
            .wait_container(&container_id, None::<WaitContainerOptions>)
            .try_collect::<Vec<_>>()
            .await?
            .first()
            .ok_or_else(|| anyhow!("missing wait response from daemon",))?
            .status_code;

        self.container_id = None;

        if status_code != 0 {
            return Err(anyhow!("non-zero exit code from container",));
        }

        // Remove the container after it successfully exits.
        self.docker
            .remove_container(&container_id, None::<RemoveContainerOptions>)
            .await?;

        Ok(())
    }

    async fn start_output_stream_task(&mut self, container_id: String) -> Result<()> {
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();

        let mut log_stream = self.docker.logs(
            &container_id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        self.stream_task = Some(tokio::task::spawn(async move {
            while let Some(Ok(item)) = log_stream.next().await {
                match item {
                    LogOutput::StdOut { message } => stdout.write_all(&message).await.unwrap(),
                    LogOutput::StdErr { message } => stderr.write_all(&message).await.unwrap(),
                    _ => {}
                }
            }
        }));

        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(container_id) = self.container_id.take() {
            self.docker
                .stop_container(&container_id, None::<StopContainerOptions>)
                .await?;

            self.docker
                .remove_container(&container_id, None::<RemoveContainerOptions>)
                .await?;
        }

        if let Some(stream_task) = self.stream_task.take() {
            stream_task.await?;
        }

        Ok(())
    }
}
