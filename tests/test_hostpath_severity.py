"""
_check_hostpath_pods (auditor_k8s.py) marcava TODO hostPath como CRITICAL,
em qualquer namespace -- inclusive kube-system, onde etcd/kube-apiserver/
kindnet/kube-proxy montam hostPath pra funcionar (certs, socket do CNI,
lib-modules do nó). Isso gera uma dezena de CRITICAL genéricos em qualquer
cluster kind/kubeadm, afogando achados de hostPath em workload de usuário
de verdade -- que são o que essa regra deveria destacar.
"""
from types import SimpleNamespace

from auditor_k8s import K8sStorageAuditor


def _fake_pod(namespace: str, pod_name: str, host_path: str, volume_name: str = "vol"):
    volume = SimpleNamespace(name=volume_name, host_path=SimpleNamespace(path=host_path))
    spec = SimpleNamespace(volumes=[volume])
    metadata = SimpleNamespace(name=pod_name, namespace=namespace)
    return SimpleNamespace(metadata=metadata, spec=spec)


def _fake_core(pods):
    return SimpleNamespace(list_pod_for_all_namespaces=lambda: SimpleNamespace(items=pods))


def test_hostpath_em_kube_system_e_low_nao_critical():
    auditor = K8sStorageAuditor(kubeconfig_yaml="")
    core = _fake_core([_fake_pod("kube-system", "etcd-node1", "/etc/kubernetes/pki/etcd")])

    findings = auditor._check_hostpath_pods(core)

    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert "kube-system" in findings[0]["reason"]


def test_hostpath_em_namespace_de_usuario_continua_critical():
    auditor = K8sStorageAuditor(kubeconfig_yaml="")
    core = _fake_core([_fake_pod("default", "app-pod", "/data")])

    findings = auditor._check_hostpath_pods(core)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_mistura_de_namespaces_classifica_cada_um_corretamente():
    auditor = K8sStorageAuditor(kubeconfig_yaml="")
    core = _fake_core([
        _fake_pod("kube-system", "kindnet-abc", "/run/xtables.lock"),
        _fake_pod("kube-node-lease", "sistema-x", "/var/lib"),
        _fake_pod("default", "meu-app", "/host/data"),
    ])

    findings = auditor._check_hostpath_pods(core)
    by_ns = {f["key"].split("/")[1]: f["severity"] for f in findings}

    assert by_ns["kube-system"] == "LOW"
    assert by_ns["kube-node-lease"] == "LOW"
    assert by_ns["default"] == "CRITICAL"
