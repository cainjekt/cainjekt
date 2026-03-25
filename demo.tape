Output demo.gif

# Terminal setup
Set FontSize 24
Set Width 1280
Set Height 720
Set TypingSpeed 100ms
Set Framerate 10
Set Padding 0
Set WaitTimeout 5m
# Set WaitPattern "[$#] $"

Hide
Type 'alias diff="diff -W $(tput cols) --color -y"'
Enter
Wait

Type "cd demo"
Enter
Wait

Type "export CLUSTER_NAME=cainjekt-demo"
Enter
Wait
Type "make kind-load CLUSTER_NAME=${CLUSTER_NAME}"
Enter
Wait

Type "kind export kubeconfig --name ${CLUSTER_NAME}"
Enter
Wait
Type "kubectl -n kube-system delete ds/cainjekt cm/cainjekt-ca-bundle --ignore-not-found=true"
Enter
Wait
Type "kubectl delete ns cainjekt-demo --ignore-not-found=true"
Enter
Wait
Type "kubectl create ns cainjekt-demo"
Enter
Wait
Type "kubectl config set-context --current --namespace=cainjekt-demo"
Enter
Wait
Type "clear"
Enter
Wait
Show

Sleep 2s

Type "bash ./generate-certs.sh"
Enter
Wait

Sleep 1s

Type "bash ./run-https-server.sh"
Enter
Wait

Sleep 1s

Type "kubectl get services"
Enter
Wait@180s

Sleep 3s

Type "clear"
Enter
Wait

Sleep 1s

Type "cat client-plain.yaml"
Enter
Wait

Sleep 3s

Type "kubectl apply -f client-plain.yaml"
Enter
Wait@90s

Sleep 5s
Hide
Sleep 30s
Show

Type "kubectl logs curl-plain"
Enter
Wait

Sleep 3s

Type "clear"
Enter
Wait

Sleep 1s

Type "kubectl -n kube-system create configmap cainjekt-ca-bundle --from-file=ca-bundle.pem=/tmp/cainjekt-demo-ca.crt"
Enter
Wait

Sleep 1s

Type "kubectl -n kube-system apply -f rbac.yaml -f daemonset.yaml"
Enter
Wait

Sleep 3s

Type "kubectl -n kube-system get daemonsets -l app=cainjekt"
Enter
Wait

Sleep 3s

Type "clear"
Enter
Wait

Sleep 1s

Type "diff client-plain.yaml client-injected.yaml"
Enter
Wait

Sleep 3s

Type "kubectl apply -f client-injected.yaml"
Enter
Wait@90s

Sleep 3s
Hide
Sleep 30s
Show

Type "kubectl logs curl-injected"
Enter
Wait

Sleep 30s
