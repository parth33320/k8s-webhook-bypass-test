"""
Kubernetes Authorization Webhook Server (Bypass Vulnerability Test)

EXPLANATION OF INTENTIONALLY MISSING 'denied' FIELD:
In Kubernetes webhook authorization (authorization.k8s.io), the decision structure returned by
a webhook server contains three status fields: 'allowed', 'denied', and 'reason'.

- 'allowed: true' explicitly ALLOWS the request.
- 'denied: true' explicitly DENIES the request (short-circuiting further authorization checks).
- 'allowed: false' WITHOUT 'denied: true' is interpreted by Kubernetes as 'NoOpinion' (abstain).

When a webhook returns 'allowed: false' and does not set 'denied: true', Kubernetes passes the request
to downstream authorizers (such as Node, RBAC, ABAC). If RBAC allows the user's action, Kubernetes grants
access despite the webhook's intention to deny it!

This server intentionally omits setting 'status.denied = true' to demonstrate and test this
authorization bypass behavior.
"""

import sys
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging to stdout
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger("webhook_server")


@app.route('/healthz', methods=['GET'])
def healthz():
    return "ok", 200


@app.route('/authorize', methods=['POST'])
def authorize():
    data = request.get_json(silent=True) or {}
    spec = data.get('spec', {})
    resource_attrs = spec.get('resourceAttributes', {})

    user = spec.get('user') or resource_attrs.get('user', 'unknown')
    verb = resource_attrs.get('verb', 'unknown')
    resource = resource_attrs.get('resource', 'unknown')
    namespace = resource_attrs.get('namespace', 'unknown')

    print(f"Extracted attributes - User: {user}, Verb: {verb}, Resource: {resource}, Namespace: {namespace}")
    sys.stdout.flush()

    log_msg = (
        f"Decision for user '{user}' requesting '{verb}' on '{resource}' in namespace '{namespace}': "
        f"allowed=false, reason='webhook policy: access denied', denied=NOT SET (treated as NoOpinion by k8s)"
    )
    logger.info(log_msg)

    response_data = {
        "apiVersion": data.get("apiVersion", "authorization.k8s.io/v1"),
        "kind": data.get("kind", "SubjectAccessReview"),
        "status": {
            "allowed": False,
            "reason": "webhook policy: access denied"
            # Intentionally NOT setting "denied": True
        }
    }

    return jsonify(response_data), 200


if __name__ == '__main__':
    # Listen on port 8443 with ssl_context='adhoc'
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')
