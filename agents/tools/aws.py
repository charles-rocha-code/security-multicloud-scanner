"""
tools/aws.py — Wrappers boto3 usados pelos agentes de infraestrutura.
Região padrão: us-east-2 (security-scanner)
"""
from __future__ import annotations

import boto3

REGION = "us-east-2"
ASG_MAIN  = "security-scanner-asg"
ASG_GREEN = "security-scanner-asg-green"
ALB_NAME  = "security-scanner-alb"
TG_MAIN   = "security-scanner-tg"
TG_GREEN  = "security-scanner-tg-green"
WAF_NAME  = "security-scanner-production-waf"
WAF_ID    = "7fa646b2-4cd6-4b54-abce-95a3444c41d3"
LOG_GROUP = "/aws/ec2/security-scanner"


# ── CloudWatch ────────────────────────────────────────────────────────────────

def get_alarms_in_alarm() -> list[dict]:
    cw = boto3.client("cloudwatch", region_name=REGION)
    resp = cw.describe_alarms(StateValue="ALARM")
    return [
        {"name": a["AlarmName"], "metric": a["MetricName"], "reason": a["StateReason"]}
        for a in resp["MetricAlarms"]
        if "security-scanner" in a["AlarmName"]
    ]


def get_cpu_average(asg_name: str, minutes: int = 5) -> float:
    import datetime
    cw = boto3.client("cloudwatch", region_name=REGION)
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(minutes=minutes)
    resp = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "AutoScalingGroupName", "Value": asg_name}],
        StartTime=start, EndTime=end,
        Period=60, Statistics=["Average"],
    )
    points = resp.get("Datapoints", [])
    return round(sum(p["Average"] for p in points) / len(points), 1) if points else 0.0


# ── Auto Scaling ──────────────────────────────────────────────────────────────

def describe_asg(asg_name: str) -> dict:
    asg = boto3.client("autoscaling", region_name=REGION)
    resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    groups = resp["AutoScalingGroups"]
    if not groups:
        return {}
    g = groups[0]
    return {
        "name":      g["AutoScalingGroupName"],
        "desired":   g["DesiredCapacity"],
        "min":       g["MinSize"],
        "max":       g["MaxSize"],
        "instances": [
            {"id": i["InstanceId"], "health": i["HealthStatus"], "lifecycle": i["LifecycleState"]}
            for i in g.get("Instances", [])
        ],
    }


def set_desired_capacity(asg_name: str, desired: int) -> None:
    boto3.client("autoscaling", region_name=REGION).set_desired_capacity(
        AutoScalingGroupName=asg_name,
        DesiredCapacity=desired,
        HonorCooldown=False,
    )


def update_asg_size(asg_name: str, min_size: int, max_size: int, desired: int) -> None:
    boto3.client("autoscaling", region_name=REGION).update_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=min_size, MaxSize=max_size, DesiredCapacity=desired,
    )


# ── ELBv2 ─────────────────────────────────────────────────────────────────────

def get_target_health(tg_name: str) -> list[dict]:
    elb = boto3.client("elbv2", region_name=REGION)
    tg_arn = elb.describe_target_groups(Names=[tg_name])["TargetGroups"][0]["TargetGroupArn"]
    health = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    return [
        {"id": t["Target"]["Id"], "state": t["TargetHealth"]["State"],
         "reason": t["TargetHealth"].get("Reason", "")}
        for t in health
    ]


def get_listener_arn() -> str:
    elb = boto3.client("elbv2", region_name=REGION)
    alb_arn = elb.describe_load_balancers(Names=[ALB_NAME])["LoadBalancers"][0]["LoadBalancerArn"]
    listeners = elb.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]
    return next(l["ListenerArn"] for l in listeners if l["Port"] == 443)


def get_tg_arn(tg_name: str) -> str:
    elb = boto3.client("elbv2", region_name=REGION)
    return elb.describe_target_groups(Names=[tg_name])["TargetGroups"][0]["TargetGroupArn"]


def switch_listener(tg_name: str) -> None:
    elb = boto3.client("elbv2", region_name=REGION)
    elb.modify_listener(
        ListenerArn=get_listener_arn(),
        DefaultActions=[{"Type": "forward", "TargetGroupArn": get_tg_arn(tg_name)}],
    )


# ── WAFv2 ─────────────────────────────────────────────────────────────────────

def get_ip_set(name: str, ip_set_id: str) -> dict:
    waf = boto3.client("wafv2", region_name=REGION)
    resp = waf.get_ip_set(Name=name, Id=ip_set_id, Scope="REGIONAL")
    return {"addresses": resp["IPSet"]["Addresses"], "lock_token": resp["LockToken"]}


def update_ip_set(name: str, ip_set_id: str, addresses: list[str], lock_token: str) -> None:
    boto3.client("wafv2", region_name=REGION).update_ip_set(
        Name=name, Id=ip_set_id, Scope="REGIONAL",
        Addresses=addresses, LockToken=lock_token,
    )


def get_waf_rules() -> list[dict]:
    waf = boto3.client("wafv2", region_name=REGION)
    resp = waf.get_web_acl(Name=WAF_NAME, Id=WAF_ID, Scope="REGIONAL")
    return [
        {"priority": r["Priority"], "name": r["Name"],
         "action": list(r.get("Action", r.get("OverrideAction", {})).keys())}
        for r in resp["WebACL"]["Rules"]
    ]


# ── CloudWatch Logs ───────────────────────────────────────────────────────────

def get_error_logs(minutes: int = 30) -> list[dict]:
    import datetime
    logs = boto3.client("logs", region_name=REGION)
    start_ms = int((datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)).timestamp() * 1000)
    resp = logs.filter_log_events(
        logGroupName=LOG_GROUP,
        filterPattern="?ERROR ?Exception ?CRITICAL ?500 ?502 ?503",
        startTime=start_ms,
        limit=50,
    )
    return [{"stream": e["logStreamName"], "message": e["message"].strip()} for e in resp.get("events", [])]
