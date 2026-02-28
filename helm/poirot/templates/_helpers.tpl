{{/*
Expand the name of the chart.
*/}}
{{- define "poirot.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "poirot.fullname" -}}
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
Chart label.
*/}}
{{- define "poirot.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "poirot.labels" -}}
helm.sh/chart: {{ include "poirot.chart" . }}
{{ include "poirot.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "poirot.selectorLabels" -}}
app.kubernetes.io/name: {{ include "poirot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Init container shared between scanner and dashboard.
Populates the writable config PVC on first run only.
*/}}
{{- define "poirot.initConfig" -}}
- name: init-config
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      if [ ! -f /config/connection.yml ]; then
        echo "Seeding connection.yml..."
        cp /seed/connection.yml /config/connection.yml
      fi
      if [ ! -f /config/.env ]; then
        echo "Seeding .env..."
        env | grep -E "^(SLACK_|SMTP_|THEHIVE_|OLLAMA_|SOURCE_)" \
          | awk -F= 'BEGIN{OFS="="} {val=substr($0,index($0,"=")+1); print $1, val}' \
          > /config/.env
      fi
  envFrom:
    - secretRef:
        name: {{ include "poirot.fullname" . }}-secret
  volumeMounts:
    - name: poirot-config
      mountPath: /config
    - name: connection-seed
      mountPath: /seed
{{- end }}
