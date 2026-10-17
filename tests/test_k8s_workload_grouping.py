"""
Ruído e rótulo errado no scan K8s, achados no scan real do cluster kind local:
- réplicas de um mesmo workload multiplicavam o mesmo finding (node-exporter,
  DaemonSet de 3 pods, gerava 3x cada hostPath = 9 CRITICAL);
- o mesmo Secret em duas env vars do mesmo container virava dois findings
  idênticos (mesma key e motivo);
- a coluna "Namespace" do relatório mostrava "Pod"/"Secret"/"PV" para os
  findings do auditor de storage (pegava o 1º segmento da key).
"""
from types import SimpleNamespace

import pytest

from auditor_k8s import finding_namespace, group_pods_by_workload


def _owner(kind, name):
    return SimpleNamespace(kind=kind, name=name, controller=True)


def _pod(name, ns="monitoring", owner=None, labels=None, containers=None, volumes=None,
         host_network=False):
    meta = SimpleNamespace(name=name, namespace=ns, labels=labels or {},
                           owner_references=[owner] if owner else [])
    spec = SimpleNamespace(containers=containers or [], volumes=volumes or [],
                           host_network=host_network, host_pid=False, host_ipc=False)
    return SimpleNamespace(metadata=meta, spec=spec)


# --- agrupamento por workload ----------------------------------------------

def test_replicas_de_daemonset_viram_um_workload():
    ds = _owner("DaemonSet", "node-exporter")
    groups = group_pods_by_workload([_pod(f"node-exporter-{s}", owner=ds) for s in "abc"])

    assert [(k, n, c) for _, k, n, c in groups] == [("DaemonSet", "node-exporter", 3)]


def test_pod_de_deployment_aponta_pro_deployment_nao_pro_replicaset():
    rs = _owner("ReplicaSet", "grafana-865699c79")
    groups = group_pods_by_workload([
        _pod("grafana-865699c79-l4bkv", owner=rs, labels={"pod-template-hash": "865699c79"}),
        _pod("grafana-865699c79-x9z2q", owner=rs, labels={"pod-template-hash": "865699c79"}),
    ])

    assert [(k, n, c) for _, k, n, c in groups] == [("Deployment", "grafana", 2)]


def test_pod_sem_dono_e_mesmo_nome_em_namespaces_diferentes_ficam_separados():
    ds = _owner("DaemonSet", "agent")
    groups = group_pods_by_workload([
        _pod("solto"),
        _pod("agent-1", ns="a", owner=ds),
        _pod("agent-2", ns="b", owner=ds),
    ])

    assert sorted((k, n, c) for _, k, n, c in groups) == [
        ("DaemonSet", "agent", 1), ("DaemonSet", "agent", 1), ("Pod", "solto", 1),
    ]


def test_static_pods_do_mesmo_node_nao_sao_agrupados():
    # etcd/apiserver/scheduler são "donos" do Node, mas são pods diferentes.
    node = _owner("Node", "control-plane")
    groups = group_pods_by_workload([
        _pod("etcd-control-plane", ns="kube-system", owner=node),
        _pod("kube-apiserver-control-plane", ns="kube-system", owner=node),
    ])

    assert sorted((k, n, c) for _, k, n, c in groups) == [
        ("Pod", "etcd-control-plane", 1), ("Pod", "kube-apiserver-control-plane", 1),
    ]


# --- auditor de storage: hostPath -------------------------------------------

def test_hostpath_de_daemonset_gera_um_finding_por_volume_nao_por_replica():
    from auditor_k8s import K8sStorageAuditor

    ds = _owner("DaemonSet", "node-exporter")
    vol = SimpleNamespace(name="root", host_path=SimpleNamespace(path="/"))
    pods = [_pod(f"node-exporter-{s}", owner=ds, volumes=[vol]) for s in "abc"]
    core = SimpleNamespace(list_pod_for_all_namespaces=lambda **k: SimpleNamespace(items=pods))

    findings = K8sStorageAuditor(kubeconfig_yaml="x")._check_hostpath_pods(core)

    assert len(findings) == 1
    f = findings[0]
    assert f["key"] == "DaemonSet/monitoring/node-exporter/volume:root"
    assert f["namespace"] == "monitoring"
    assert f["severity"] == "CRITICAL"
    assert "(3 pods)" in f["reason"]


# --- auditor autenticado: workload e Secret em env var ---------------------

def _auth_auditor(pods):
    from auditor_k8s_authenticated import K8sAuthenticatedAuditor

    auditor = K8sAuthenticatedAuditor.__new__(K8sAuthenticatedAuditor)
    auditor.timeout = 1
    auditor.core = SimpleNamespace(
        list_namespaced_pod=lambda ns, **k: SimpleNamespace(items=pods),
        list_namespaced_secret=lambda ns, **k: SimpleNamespace(items=[]),
        list_namespaced_config_map=lambda ns, **k: SimpleNamespace(items=[]),
    )
    return auditor


def _container(name="main", privileged=False, env=None):
    sc = SimpleNamespace(privileged=privileged, run_as_user=1000, run_as_non_root=True)
    return SimpleNamespace(name=name, security_context=sc,
                           resources=SimpleNamespace(limits={"cpu": "1"}), env=env or [])


def test_container_privilegiado_em_daemonset_vira_um_finding():
    ds = _owner("DaemonSet", "kube-agent")
    pods = [_pod(f"kube-agent-{s}", ns="apps", owner=ds, containers=[_container(privileged=True)])
            for s in "abc"]

    findings = _auth_auditor(pods)._check_workload_security(["apps"])

    priv = [f for f in findings if "privileged" in f["reason"]]
    assert len(priv) == 1
    assert priv[0]["severity"] == "CRITICAL"
    assert priv[0]["resource_name"] == "kube-agent/main"
    assert "(3 pods)" in priv[0]["reason"]


def test_mesmo_secret_em_duas_env_vars_vira_um_finding_com_as_duas():
    def _env(var, secret):
        ref = SimpleNamespace(secret_key_ref=SimpleNamespace(name=secret))
        return SimpleNamespace(name=var, value_from=ref)

    rs = _owner("ReplicaSet", "grafana-865699c79")
    c = _container("grafana", env=[_env("GF_ADMIN_USER", "monitoring-grafana"),
                                   _env("GF_ADMIN_PASSWORD", "monitoring-grafana"),
                                   _env("DB_PASS", "outro-secret")])
    pod = _pod("grafana-865699c79-l4bkv", owner=rs, labels={"pod-template-hash": "865699c79"},
               containers=[c])

    findings = _auth_auditor([pod])._check_secrets_configmaps(["monitoring"])

    env_findings = sorted(f["reason"] for f in findings if "env var" in f["reason"])
    assert env_findings == [
        "Secret 'monitoring-grafana' montado como env var (GF_ADMIN_PASSWORD, GF_ADMIN_USER)",
        "Secret 'outro-secret' montado como env var (DB_PASS)",
    ]
    keys = [f["key"] for f in findings if "env var" in f["reason"]]
    assert len(keys) == len(set((k, r) for k, r in zip(keys, env_findings)))


# --- coluna Namespace do relatório -----------------------------------------

@pytest.mark.parametrize("finding,esperado", [
    ({"key": "Pod/monitoring/node-exporter-x/volume:root"}, "monitoring"),
    ({"key": "Secret/microservices-lab/app-secrets[POSTGRES_PASSWORD]"}, "microservices-lab"),
    ({"key": "DaemonSet/monitoring/node-exporter/volume:root"}, "monitoring"),
    ({"key": "PV/pvc-123"}, "cluster"),
    ({"key": "StorageClass/standard"}, "cluster"),
    ({"key": "default/Role/teste-perigoso", "namespace": "default"}, "default"),
    ({"key": "cluster/ClusterRole/admin", "namespace": "-"}, "cluster"),
    ({"key": "monitoring/Container/grafana/grafana"}, "monitoring"),
])
def test_finding_namespace(finding, esperado):
    assert finding_namespace(finding) == esperado


def test_relatorio_k8s_leva_o_namespace_certo_nos_itens():
    from generate_report import ProfessionalReportGenerator

    scan = {"provider": "KUBERNETES", "files": [
        {"key": "Pod/monitoring/node-exporter-x/volume:root", "severity": "CRITICAL", "category": "Storage"},
        {"key": "Secret/microservices-lab/app-secrets[POSTGRES_PASSWORD]", "severity": "CRITICAL", "category": "Storage"},
        {"key": "PV/pvc-123", "severity": "CRITICAL", "category": "Storage"},
        {"key": "default/Role/teste-perigoso", "namespace": "default", "severity": "CRITICAL", "category": "RBAC"},
    ]}

    vulns = ProfessionalReportGenerator._analyze_vulnerabilities(SimpleNamespace(scan_data=scan))

    got = {i["file"]: i["namespace"] for v in vulns for i in v["items"]}
    assert got == {
        "Pod/monitoring/node-exporter-x/volume:root": "monitoring",
        "Secret/microservices-lab/app-secrets[POSTGRES_PASSWORD]": "microservices-lab",
        "PV/pvc-123": "cluster",
        "default/Role/teste-perigoso": "default",
    }
