{{/*
Expand the name of the chart.
*/}}
{{- define "cainjekt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cainjekt.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cainjekt.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cainjekt.labels" -}}
helm.sh/chart: {{ include "cainjekt.chart" . }}
{{ include "cainjekt.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cainjekt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cainjekt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "cainjekt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cainjekt.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Namespace
*/}}
{{- define "cainjekt.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Image reference: repository@digest when a digest is set, else repository:tag
(tag defaults to appVersion).
*/}}
{{- define "cainjekt.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag | toString) -}}
{{- end -}}
{{- end }}

{{/*
CA bundle source, validated.
*/}}
{{- define "cainjekt.caSource" -}}
{{- $src := .Values.caBundle.source -}}
{{- if not (has $src (list "configMap" "inline")) -}}
{{- fail (printf "caBundle.source must be configMap or inline (got %q)" $src) -}}
{{- end -}}
{{- if and (eq $src "inline") (not .Values.caBundle.inline) -}}
{{- fail "caBundle.source=inline requires caBundle.inline (PEM), e.g. --set-file caBundle.inline=ca.pem" -}}
{{- end -}}
{{- $src -}}
{{- end }}

{{/*
ConfigMap name for the CA bundle (configMap and inline sources).
*/}}
{{- define "cainjekt.caBundleConfigMapName" -}}
{{- if eq .Values.caBundle.source "inline" -}}
{{- printf "%s-ca-bundle" (include "cainjekt.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- required "caBundle.configMap.name is required" .Values.caBundle.configMap.name -}}
{{- end -}}
{{- end }}

{{/*
Whether the health/metrics HTTP server is enabled, validated against the
features that need it.
*/}}
{{- define "cainjekt.httpEnabled" -}}
{{- $needs := or .Values.probes.liveness.enabled .Values.probes.readiness.enabled .Values.metrics.service.enabled .Values.metrics.serviceMonitor.enabled -}}
{{- if and $needs (not .Values.httpServer.enabled) -}}
{{- fail "probes and metrics.service/serviceMonitor require httpServer.enabled=true (and a cainjekt image with --http-addr)" -}}
{{- end -}}
{{- if .Values.httpServer.enabled -}}true{{- end -}}
{{- end }}
