Local test harness proving that a Kubernetes authorization webhook returning {allowed: false} without {denied: true} is treated as NoOpinion and bypassed by downstream RBAC.
