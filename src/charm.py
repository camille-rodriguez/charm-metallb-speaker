#!/usr/bin/env python3
# Copyright 2020 Camille Rodriguez
# See LICENSE file for licensing details.

from base64 import b64encode
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import logging
import os
import random
import string


from ops.charm import CharmBase
from ops.main import main
from ops.framework import StoredState
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
)

import utils

logger = logging.getLogger(__name__)


class MetallbSpeakerCharm(CharmBase):
    _stored = StoredState()

    NAMESPACE = os.environ["JUJU_MODEL_NAME"]

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.start, self.on_start)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self._stored.set_default(things=[])

    def _on_config_changed(self, _):
        current = self.model.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)

    def on_start(self, event):
        if not self.framework.model.unit.is_leader():
            return

        logging.info('Setting the pod spec')
        self.framework.model.unit.status = MaintenanceStatus("Configuring pod")
        secret = self._random_secret(128)

        self.framework.model.pod.set_spec(
            {
                'version': 3,
                'serviceAccount': {
                    'roles' :  [{
                        'global': True,
                        'rules': [
                            {
                                'apiGroups': [''],
                                'resources': ['services', 'endpoints', 'nodes'],
                                'verbs': ['get', 'list', 'watch'],
                            },
                            {
                                'apiGroups': [''],
                                'resources': ['events'],
                                'verbs': ['create', 'patch'],
                            },
                            {
                                'apiGroups': ['policy'],
                                'resourceNames': ['speaker'],
                                'resources': ['podsecuritypolicies'],
                                'verbs': ['use'],
                            },
                        ],
                    },
                  ],
                },
                'containers': [{
                    'name': 'speaker',
                    'image': 'metallb/speaker:v0.9.3',
                    'imagePullPolicy': 'Always',
                    'ports': [{
                        'containerPort': 7472,
                        'protocol': 'TCP',
                        'name': 'monitoring'
                    }],
                    'envConfig': {
                        'METALLB_NODE_NAME': {
                            'field': {
                                'path': 'spec.nodeName',
                                'api-version': 'v1'
                            }
                        },
                        'METALLB_HOST': {
                            'field': {
                                'path': 'status.hostIP',
                                'api-version': 'v1'
                            }
                        },
                        'METALLB_ML_BIND_ADDR': {
                            'field': {
                                'path': 'status.podIP',
                                'api-version': 'v1'
                            }
                        },
                        'METALLB_ML_LABELS': "app=metallb,component=speaker",
                        'METALLB_ML_NAMESPACE': {
                            'field': {
                                'path': 'metadata.namespace',
                                'api-version': 'v1'
                            }
                        },
                        'METALLB_ML_SECRET_KEY': {
                            'secret': {
                                'name': 'memberlist',
                                'key': 'secretkey'
                            }
                        }
                    },
                    # constraint fields do not exist in pod_spec
                    # bug : https://bugs.launchpad.net/juju/+bug/1893123
                    # 'cpu': 100,
                    # 'memory': 100,
                    # 'resources': {
                    #     'limits': {
                    #         'cpu': '100m',
                    #         'memory': '100Mi',
                    #     }
                    # },
                    'kubernetes': {
                        'securityContext': {
                            'allowPrivilegeEscalation': False,
                            'readOnlyRootFilesystem': True,
                            'capabilities': {
                                'add': ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN'],
                                'drop': ['ALL']
                            },

                        },
                        # fields do not exist in pod_spec
                        # 'TerminationGracePeriodSeconds': 2, 
                    },
                }],
                'kubernetesResources': {
                    'secrets': [
                            {
                                'name': 'memberlist',
                                'type': 'Opaque',
                                'data': {
                                    'secretkey': b64encode(secret.encode('utf-8')).decode('utf-8')
                                }
                            }
                        ]
                },
                'service': {
                    'annotations': {
                        'prometheus.io/port': '7472',
                        'prometheus.io/scrape': 'true'
                    }
                },
            },
        )

        logging.info('launching create_pod_security_policy_with_k8s_api')
        self.create_pod_security_policy_with_k8s_api()
        self.create_namespaced_role_with_api(
            name='config-watcher',
            labels={'app': 'metallb'},
            resources=['configmaps'],
            verbs=['get','list','watch']
        )
        self.create_namespaced_role_with_api(
            name='pod-lister',
            labels={'app': 'metallb'},
            resources=['pods'],
            verbs=['list']
        )
        logging.info('Launching bind_role_with_api')
        self.bind_role_with_api(
            name='config-watcher', 
            labels={'app': 'metallb'}, 
            subject_name='speaker'
        )
        self.bind_role_with_api(
            name='pod-lister', 
            labels={'app': 'metallb'}, 
            subject_name='speaker'
        )
        self.framework.model.unit.status = ActiveStatus("Ready")

    def create_pod_security_policy_with_k8s_api(self):
        # Using the API because of LP:1886694
        self._load_kube_config()

        metadata = client.V1ObjectMeta(
            namespace = self.NAMESPACE,
            name = 'speaker',
            labels = {'app':'metallb'}
        )
        policy_spec = client.PolicyV1beta1PodSecurityPolicySpec(
            allow_privilege_escalation = False,
            allowed_capabilities = [
                'NET_ADMIN',
                'NET_RAW',
                'SYS_ADMIN',
            ],
            default_allow_privilege_escalation = False,
            fs_group = client.PolicyV1beta1FSGroupStrategyOptions(
                rule = 'RunAsAny'
            ),
            host_ipc = False,
            host_network = True,
            host_pid = False,
            host_ports = [client.PolicyV1beta1HostPortRange(
                max = 7472,
                min = 7472,
            )],
            privileged = True,
            read_only_root_filesystem = True,
            required_drop_capabilities = ['ALL'],
            run_as_user = client.PolicyV1beta1RunAsUserStrategyOptions(
                rule = 'RunAsAny'
            ),
            se_linux = client.PolicyV1beta1SELinuxStrategyOptions(
                rule = 'RunAsAny',
            ),
            supplemental_groups = client.PolicyV1beta1SupplementalGroupsStrategyOptions(
                rule = 'RunAsAny'
            ),
            volumes = ['configMap', 'secret', 'emptyDir'],
        )

        body = client.PolicyV1beta1PodSecurityPolicy(metadata=metadata, spec=policy_spec)

        with client.ApiClient() as api_client:
            api_instance = client.PolicyV1beta1Api(api_client)
            try:
                api_instance.create_pod_security_policy(body, pretty=True)
            except ApiException as err:
                logging.exception("Exception when calling PolicyV1beta1Api->create_pod_security_policy.")
                if err.status != 409:
                    # ignoring 409 (AlreadyExists) errors
                    self.framework.model.unit.status = \
                        BlockedStatus("An error occured during instantiation. Please check the logs.")


    def create_namespaced_role_with_api(self, name, labels, resources, verbs, api_groups=['']):
        # Using API because of bug https://github.com/canonical/operator/issues/390
        self._load_kube_config()

        with client.ApiClient() as api_client:
            api_instance = client.RbacAuthorizationV1Api(api_client)
            body = client.V1Role(
                metadata = client.V1ObjectMeta(
                    name = name,
                    namespace = self.NAMESPACE,
                    labels = labels
                ),
                rules = [client.V1PolicyRule(
                    api_groups = api_groups,
                    resources = resources,
                    verbs = verbs,
                )]
            )
            try:
                api_instance.create_namespaced_role(self.NAMESPACE, body, pretty=True)
            except ApiException as err:
                logging.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role.")
                if err.status != 409:
                    # ignoring 409 (AlreadyExists) errors
                    self.framework.model.unit.status = \
                        BlockedStatus("An error occured during instantiation. Please check the logs.")

    def bind_role_with_api(self, name, labels, subject_name, subject_kind='ServiceAccount'):
        # Using API because of bug https://github.com/canonical/operator/issues/390
        self._load_kube_config()

        with client.ApiClient() as api_client:
            api_instance = client.RbacAuthorizationV1Api(api_client)
            body = client.V1RoleBinding(
                metadata = client.V1ObjectMeta(
                    name = name,
                    namespace = self.NAMESPACE,
                    labels = labels
                ),
                role_ref = client.V1RoleRef(
                    api_group = 'rbac.authorization.k8s.io',
                    kind = 'Role',
                    name = name,
                ),
                subjects = [
                    client.V1Subject(
                        kind = subject_kind,
                        name = subject_name
                    ),
                ]
            )
            try:
                api_instance.create_namespaced_role_binding(self.NAMESPACE, body, pretty=True)
            except ApiException as err:
                logging.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role_binding.")
                if err.status != 409:
                    # ignoring 409 (AlreadyExists) errors
                    self.framework.model.unit.status = \
                        BlockedStatus("An error occured during instantiation. Please check the logs.")

    def _random_secret(self, length):
        letters = string.ascii_letters
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str

    def _load_kube_config(self):
        # TODO: Remove this workaround when bug LP:1892255 is fixed
        from pathlib import Path
        os.environ.update(
            dict(
                e.split("=")
                for e in Path("/proc/1/environ").read_text().split("\x00")
                if "KUBERNETES_SERVICE" in e
            )
        )
        # end workaround
        config.load_incluster_config()

if __name__ == "__main__":
    main(MetallbSpeakerCharm)
