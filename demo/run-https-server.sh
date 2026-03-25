#! /bin/bash

kubectl create secret generic https-server-tls --from-file=tls.crt=/tmp/cainjekt-demo-server.crt --from-file=tls.key=/tmp/cainjekt-demo-server.key
kubectl apply -f https-server.yaml
