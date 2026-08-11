{{- define "hematite.fullname" -}}
{{ .Release.Name }}
{{- end }}

{{- define "hematite.selectorLabels" -}}
app.kubernetes.io/name: hematite
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hematite.labels" -}}
{{ include "hematite.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
