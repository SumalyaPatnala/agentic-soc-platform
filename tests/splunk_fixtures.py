"""TEST FIXTURES ONLY -- these are not BOTS v3 evidence.

Every dictionary in this module is a hand-written *schema-shape* fixture whose only
purpose is to exercise the field-alias logic in ``app.ingestion.splunk`` for the
sourcetypes BOTS v3 contains. They are not exported from the BOTS v3 dataset, they
are not a synthetic incident dataset, and they describe no attacker activity. Any
finding to be investigated must come from real events exported out of Splunk.

Identifiers are deliberately non-routable or reserved for documentation:
RFC 5737 ranges (``203.0.113.0/24``, ``198.51.100.0/24``), RFC 1918 (``10.0.0.0/8``),
and placeholder AWS account/instance IDs.

None of these fixtures carries an ``index`` field. ``app.services.validation`` treats
``index=botsv3`` on a record as evidence that it came from a real BOTS v3 export, so
omitting it here makes it impossible for a fixture to be mistaken for real data.
"""

from __future__ import annotations

from typing import Any

# Shape of an `index=botsv3 sourcetype=aws:cloudtrail` row exported as JSON.
# `DescribeInstances` is a read-only API call, chosen so the fixture carries no
# implied narrative.
CLOUDTRAIL_FIXTURE: dict[str, Any] = {
    "_time": "2018-08-20T13:01:46.000+00:00",
    "source": (
        "s3://example-cloudtrail-bucket/AWSLogs/111111111111/CloudTrail/"
        "us-west-2/2018/08/20/example.json.gz"
    ),
    "sourcetype": "aws:cloudtrail",
    "host": "111111111111",
    "eventTime": "2018-08-20T13:01:46Z",
    "eventName": "DescribeInstances",
    "eventSource": "ec2.amazonaws.com",
    "awsRegion": "us-west-2",
    "userName": "example-user",
    "sourceIPAddress": "203.0.113.25",
    "userAgent": "aws-cli/1.15.40 Python/3.6.5",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLEPRINCIPALID",
        "accountId": "111111111111",
    },
}

# Shape of an `index=botsv3 sourcetype=aws:cloudwatch:guardduty` row. Exercises the
# `instance_id` host fallback, the `signature` event-name alias, and a numeric
# severity. The finding type is a public GuardDuty enum value used here purely as a
# string placeholder.
GUARDDUTY_FIXTURE: dict[str, Any] = {
    "_time": 1534770106.0,
    "source": "guardduty",
    "sourcetype": "aws:cloudwatch:guardduty",
    "signature": "Recon:EC2/PortProbeUnprotectedPort",
    "severity": 2.0,
    "accountId": "111111111111",
    "region": "us-west-2",
    "instance_id": "i-0example1234abcd",
    "src_ip": "198.51.100.14",
    "dest_ip": "10.0.1.42",
}

# Shape of an `index=botsv3 sourcetype=XmlWinEventLog:...Sysmon...` row. Exercises the
# `Computer`/`Account_Name`/`EventCode` Windows aliases, a `_time` string with no UTC
# offset, and a non-JSON `_raw` that must be skipped rather than parsed.
SYSMON_FIXTURE: dict[str, Any] = {
    "_time": "2018-08-20 13:01:46",
    "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "Computer": "EXAMPLE-WKS01.example.local",
    "EventCode": "1",
    "Account_Name": "example.user",
    "Image": "C:\\Windows\\System32\\whoami.exe",
    "ProcessId": "4242",
    "_raw": (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1</EventID></System></Event>"
    ),
}
