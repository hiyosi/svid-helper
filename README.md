# pod-svid-manager

If you want to treat the SVID as a file, this helper will help you to issue and rotate the SVID.
The helper behaves as a Pod's Sidecar.

## Usage

```
Usage of :
      --log-level string             Set the minimum level for logging [HELPER_LOG_LEVEL] (default "debug")
      --mode string                  Behavior of the helper, 'init' or 'refresh' [HELPER_MODE] (default "init")
      --pod-spiffe-id string         The SPIFFE ID which is allocated to the Pod. SVID output to svid-path is associated with the specified SPIFFE ID [HELPER_POD_SPIFFE_ID]
      --svid-path string             Path to the directory where output the SVIDs [HELPER_SVID_PATH] (default "/tmp")
      --workload-api-socket string   Path to the Workload API served by SPIRE Agent [HELPER_WORKLOAD_API_SOCKET] (default "/var/run/spire/agent.sock")
```

## Architecture

pod-svid-helper has 2 different behavior that can be specified by `--mode` flag.

### 'init' mode

The helper fetch the SVID only once and writes it to a file in given path(`--svid-path`).
If the helper fails to fetch the SVID, the helper exits with error.

'init' mode helper should run as initContainer.

e.g.,
```yaml
      initContainers:
      - name: init-svid
        args:
        - --mode=init
        - --workload-api-socket=/var/run/spire/agent.sock
        - --pod-spiffe-id=spiffe://example.org/workload/my-pod
        - --svid-path=/var/run/secret
        image: hiyosi/pod-svid-helper:latest
        imagePullPolicy: Always
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /var/run/spire
          readOnly: false
        - name: svid-dir
          mountPath: /var/run/secret
```

### 'refresh' mode

The helper watches update of SVID.
When the SVID is rotated, the helper receives the update and updates the SVID file with its contents.
If the helper fails to update the SVID, the helper only outputs the logs. this means 'refresh' mode helper doesn't exit when an error occur, continue to watch the update. 

'refresh' mode helper should run as sidecar container.

e.g.,
```yaml
      containers:
      - name: refresh-svid
        args:
        - --mode=refresh
        - --workload-api-socket=/var/run/spire/agent.sock
        - --pod-spiffe-id=spiffe://example.org/workload/my-pod
        - --svid-path=/var/run/secret
        image: hiyosi/pod-svid-helper:latest
        imagePullPolicy: Always
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /var/run/spire
          readOnly: false
        - name: svid-dir
          mountPath: /var/run/secret
```

## example

- Create Kubernetes Cluster
```
$ kind create cluster --image kindest/node:v1.17.2 --name spire-test --config example/kind-config.yaml
```

- Deploy SPIRE Server and Agent  
```
$ git clone https://github.com/spiffe/spire-examples.git
$ cd spire-examples/examples/k8s/simple_psat
$ kubectl apply -f spire-server.yaml
$ kubectl apply -f spire-agent.yaml
```

- Create Registration Entry

```
# bin/spire-server entry create \ 
  -registrationUDSPath /tmp/spire-registration.sock \ 
  -spiffeID spiffe://example.org/k8s/node/worker \ 
  -selector k8s_psat:cluster:demo-cluster -node

# bin/spire-server entry create \
      -registrationUDSPath /tmp/spire-registration.sock \
      -parentID spiffe://example.org/k8s/node/worker \
      -spiffeID spiffe://example.org/workload/nginx \
      -selector k8s:ns:default \
      -selector k8s:sa:nginx \
      -selector k8s:pod-label:app:my-nginx
```

- Deploy exsample application

```
$ kubectl apply -f example/my-nginx.yaml
```
