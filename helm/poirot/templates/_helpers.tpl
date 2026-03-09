{{/*
Common labels
*/}}
{{- define "poirot.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Namespace — always use values.namespace
*/}}
{{- define "poirot.namespace" -}}
{{ .Values.namespace | default "poirot" }}
{{- end }}
