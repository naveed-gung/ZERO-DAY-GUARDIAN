# EduFlow workload demo

This example uses the original [EduFlow favicon](https://github.com/naveed-gung/eduflow/blob/main/client/public/favicon.svg) from Naveed Gung’s learning platform. The copy is verified against Git blob `a103d755ce09e9e89e897dadbf2bdc16cab42b8e`.

## Run it

From the ZERO-DAY-GUARDIAN repository root, with Python 3.9+ and JDK 21 available:

```sh
python examples/eduflow/demo.py
```

Use `python3` if that is the name of your Python executable. Set `JAVA_HOME` to your JDK directory if `javac` is absent from PATH. Python’s standard library and the JDK are sufficient. The program runs offline and requires zero cloud spend.

| Step | What runs | What it demonstrates |
| --- | --- | --- |
| EduFlow asset | A local, in-process HTTP response returns the upstream favicon. | A real artifact from EduFlow is present and verified byte for byte. |
| Normal replay | A synthetic process-start record goes through Guardian’s 384-byte decoder and rules. | The routine fixture produces no finding. |
| Alert replay | A synthetic event record goes through the same production decoder and rules. | The rule returns a critical container-escape signal, MITRE ATT&CK T1611, and its rule score. |

The two records are hand-built fixtures. The HTTP request does not generate them. The demo exercises the decoder and detection rule, while the kernel sensor, full Spring service, deployment, and dataplane require a Linux test cluster. It serves the favicon only. EduFlow’s React app, database and authentication are outside this demo.

## Portfolio walkthrough

1. Show the asset verification and normal record in the terminal.
2. Point out the synthetic alert and explain the difference between its rule score and proof of a successful escape.
3. Open [the live-cluster verification guide](../../docs/response-hardening.md) to show where workload attribution and containment are verified separately.

For live capture, deploy Guardian and a disposable copy of a workload on a local Linux Kubernetes cluster, then exercise an ordinary request and check the ring-buffer read and decode-error metrics. The offline demo keeps its fixtures reproducible across Windows and Linux.
