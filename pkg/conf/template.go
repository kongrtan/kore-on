package conf

const Template = `#koreon.toml
[koreon]
version = "1.0.0"
cluster-type = "small"
cluster-name = "ml-central2"
debug-mode = true
#closed-network = true
local-repository = "http://192.168.1.251:8080"
cert-validity-days = 3650
#install-dir = "/var/lib/knit"

[kubernetes]
version = "1.20.2"
container-runtime = "containerd"
kube-proxy-mode = "ipvs"
api-sans = ["192.168.88.161", "192.168.1.9"]
vxlan-mode = true
[kubernetes.etcd]
ip = ["192.168.88.161","192.168.88.162", "192.168.88.163"]
private-ip = ["172.33.88.161","172.33.88.162", "172.33.88.163"]
encrypt-secret = true

[node-pool]
data-dir = "/data"

[node-pool.security]
ssh-user-id = "ubuntu"
private-key-path = "/Users/okpiri/cert/hostacloud/id_rsa"

[node-pool.master]
ip = ["192.168.88.161","192.168.88.162", "192.168.88.163"]
private-ip = ["172.33.88.161","172.33.88.162", "172.33.88.163"]
lb-ip = "192.168.88.161"
#external-lb = "192.168.88.161"
#node-port-url = "192.168.88.161"
node-port-range = "30000-32767"
#isolated = true
haproxy-install = true

[node-pool.node]
ip = [ "192.168.88.164"]
private-ip = ["172.33.88.164"]

[shared-storage]
install = false
storage-ip = "192.168.88.11"
volume-dir = "/data/nvme/mlops/161"
volume-size = 1000

[private-registry]
install = false
registry-ip = "regi.k3.acornsoft.io"
data-dir = "/data/harbor"
public-cert = true
[private-registry.cert-file]
ssl-certificate = ""
ssl-certificate-key = ""
`
