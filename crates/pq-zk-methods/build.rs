fn main() {
    #[cfg(feature = "reproducible-build")]
    {
        use std::{collections::HashMap, path::PathBuf};

        use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

        const GUEST_BUILDER: &str =
            "r0.1.94.1@sha256:c2f63fdd720337c0727e05c5e1733083baba04c00a864a89b0e3f4f8d92617be";
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("pq-zk methods crate must live under the workspace crates directory")
            .to_path_buf();
        let docker = DockerOptionsBuilder::default()
            .root_dir(workspace_root)
            .docker_container_tag(GUEST_BUILDER)
            .build()
            .expect("valid reproducible RISC0 Docker options");
        let guest = GuestOptionsBuilder::default()
            .use_docker(docker)
            .build()
            .expect("valid reproducible RISC0 guest options");
        let mut options = HashMap::new();
        options.insert("activechain-pq-zk-guest", guest);
        risc0_build::embed_methods_with_options(options);
    }

    #[cfg(not(feature = "reproducible-build"))]
    risc0_build::embed_methods();
}
