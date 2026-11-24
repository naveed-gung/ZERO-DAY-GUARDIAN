# Bazaar and Guardian

Run `python -B examples/bazaar_demo.py` from the Guardian repo root with Python 3.9+, JDK 21, and Node.js 24+. If necessary, point `JAVA_HOME` to the JDK. The demo runs offline.

The first step runs Bazaar’s actual shared permission contract. A customer lacks `inventory:manage` and the operations role has it. The bundled TypeScript is verified against Git blob `ba193dc01b3d5407ac3b8a9ccea57533f70bbcec` and includes Bazaar’s MIT license. [Upstream source](https://github.com/naveed-gung/bazaar/blob/main/packages/shared/src/permissions.ts)

The second step feeds two synthetic records with a Bazaar workload name into Guardian’s actual wire decoder and detection rules. The normal process start generates no alert. The synthetic runtime signal emits `CRITICAL / T1611`. No exploits, Kubernetes writes, or external requests occur.

The demo runs the shared permission module without deploying Bazaar’s storefront, API, database, or Firebase. The replay does not capture live kernel events. For that stage, follow the [Linux cluster verification guide](../../docs/response-hardening.md).
