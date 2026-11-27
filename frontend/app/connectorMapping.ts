// Maps a source system's webhook payload onto a RelayOps relay, using a connector's payload field
// definitions. This is the preview used by the Connections screen; it sends nothing anywhere.

export type PayloadFieldDef = {
  path: string;
  type: string;
  required: boolean;
  mandatory?: boolean;
  maps_to?: string;
  description?: string;
};
export type SeverityMapEntry = { from: string; to: string };

export const MAPS_TO_TARGETS = ["dedup_key", "title", "description", "severity", "service", "status", "url"] as const;
export const SEVERITIES = ["critical", "error", "warning", "info"] as const;

/**
 * Reads a dot path such as `alerts.0.labels.alertname`. Numeric parts index arrays. When the path
 * continues through a string that holds a JSON object (an SNS `Message`, for example) the string is decoded.
 */
export function resolvePath(root: unknown, path: string): unknown {
  let current: unknown = root;
  for (const part of path.split(".")) {
    if (typeof current === "string") {
      try {
        const parsed = JSON.parse(current);
        if (parsed && typeof parsed === "object") current = parsed;
      } catch {
        return undefined;
      }
    }
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(part)) return undefined;
      current = current[Number(part)];
    } else if (current && typeof current === "object") {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
    if (current === undefined || current === null) return undefined;
  }
  return current;
}

const asText = (value: unknown): string | undefined =>
  typeof value === "string" ? value : typeof value === "number" || typeof value === "boolean" ? String(value) : undefined;

export type MappingPreview = {
  relay: { dedup_key: string; title: string; description: string; severity: string; source: string; service: string; status: string; url: string };
  /** Required fields whose path found nothing in the payload. */
  missing: { path: string; maps_to: string }[];
  notes: string[];
};

export function previewMapping(
  fields: PayloadFieldDef[],
  severityMap: SeverityMapEntry[],
  payload: unknown,
  config: Record<string, string>,
  connectorKey: string,
): MappingPreview {
  const value = (target: string): string | undefined => {
    const field = fields.find((f) => f.maps_to === target && f.path.trim());
    return field ? asText(resolvePath(payload, field.path.trim())) : undefined;
  };
  const notes: string[] = [];
  const missing = fields
    .filter((f) => f.required && f.path.trim() && asText(resolvePath(payload, f.path.trim())) === undefined)
    .map((f) => ({ path: f.path, maps_to: f.maps_to || "" }));

  const rawSeverity = value("severity");
  const fallback = (SEVERITIES as readonly string[]).includes(config.default_severity) ? config.default_severity : "warning";
  let severity = fallback;
  if (rawSeverity !== undefined) {
    const lowered = rawSeverity.trim().toLowerCase();
    const mapped = severityMap.find((m) => m.from.toLowerCase() === lowered);
    if (mapped) severity = mapped.to;
    else if ((SEVERITIES as readonly string[]).includes(lowered)) severity = lowered;
    else notes.push(`Severity "${rawSeverity}" is not recognised; using the default (${fallback}).`);
  } else if (fields.some((f) => f.maps_to === "severity" && f.path.trim())) {
    notes.push(`No severity found in the payload; using the default (${fallback}).`);
  }
  const service = value("service") ?? config.default_service ?? "";
  if (value("service") === undefined && config.default_service) notes.push("No service found in the payload; using the default service.");
  return {
    relay: {
      dedup_key: value("dedup_key") ?? "",
      title: value("title") ?? "",
      description: value("description") ?? "",
      severity,
      source: config.source || connectorKey,
      service,
      status: value("status") ?? "",
      url: value("url") ?? "",
    },
    missing,
    notes,
  };
}
