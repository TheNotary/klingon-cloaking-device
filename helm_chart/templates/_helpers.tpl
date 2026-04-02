{{/*
Resolve the namespace for all resources.
Priority: .Values.namespaceOverride > .Release.Namespace
*/}}
{{- define "kcd.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}
