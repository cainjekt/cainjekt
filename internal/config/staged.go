package config

// Per-container CA staging. The NRI plugin stages the CA files on the host
// under the dynamic CA root and bind-mounts that directory read-only into the
// container at ContainerCADir. The paths are therefore fixed and can be put on
// the OCI spec env, which is decided before the hook has inspected the image.
const (
	// ContainerCADir is deliberately not /etc/cainjekt: the hook writes
	// hook-context.json there inside the rootfs and a mount would shadow it.
	ContainerCADir = "/etc/cainjekt-ca"

	// DynamicCAFileName holds only the organization CA.
	DynamicCAFileName = "ca-bundle.pem"
	// MergedCAFileName holds system roots + organization CA.
	MergedCAFileName = "ca-bundle-merged.pem"

	// ContainerOrgCA is the bare org CA, for additive consumers only.
	ContainerOrgCA = ContainerCADir + "/" + DynamicCAFileName
	// ContainerMergedCA is for trust-REPLACING consumers, which would lose the
	// public roots if pointed at the bare org CA.
	ContainerMergedCA = ContainerCADir + "/" + MergedCAFileName
)
