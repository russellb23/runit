"use client";

import {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

type Incident = {
  id: string;
  incident_number: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  service: string;
  dedup_key: string;
  assignee?: string | null;
  created_at: string;
  updated_at: string;
};
type Policy = {
  id: string;
  name: string;
  description: string;
  timezone: string;
  repeat_count: number;
  repeat_every_minutes: number;
  steps: { delay_minutes: number; target_type: string; target: string }[];
};
type NotifyUser = {
  handle: string;
  team: string;
  groups: string[];
  channels: Record<string, { destination: string; active: boolean }>;
};
type EventRow = {
  id: number;
  kind: string;
  actor: string;
  note: string;
  created_at: string;
};
type ApiKey = {
  id: string;
  name: string;
  role: string;
  active: boolean;
  last_used_at?: string | null;
  expires_at?: string | null;
};
type Delivery = {
  id: string;
  channel: string;
  status: string;
  attempts: number;
  next_attempt_at: string;
  last_error: string;
};
type TenantRecord = {
  id: string;
  name: string;
  slug: string;
  created_at: string;
};
type TenantMenu = { tenant: TenantRecord; x: number; y: number };
type IncidentMenu = { incident: Incident; x: number; y: number };
type ConnectorDefinition = {
  key: string;
  name: string;
  category: string;
  supported: boolean;
  summary: string;
  fields: string[];
};
type PayloadField = {
  path: string;
  type: "string" | "number" | "boolean" | "object" | "array";
  required: boolean;
  description: string;
};
type TenantIntegration = {
  id: string;
  connector_key: string;
  name: string;
  enabled: boolean;
  configuration: Record<string, unknown>;
  credential_reference?: string | null;
  validation_status: string;
  last_validated_at?: string | null;
};
type AnalyticsCounts = {
  total: number;
  by_integration: [string, number][];
  by_user: [string, number][];
};
type ChartPoint = { at: number; total: number };
type AuthAccount = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  active: boolean;
  is_product_owner?: boolean;
  created_at: string;
};
type BrowserSession = {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  user_agent: string;
  current: boolean;
};
type OnCallSchedule = {
  id: string;
  name: string;
  timezone: string;
  rotation_interval_minutes: number;
  rotation_starts_at: string;
  members: string[];
  created_at: string;
  updated_at: string;
};
const pretty = (d: string) =>
  new Date(d).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
const localDateTime = (value: string) => {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
};
const roles = ["owner", "admin", "responder", "integration", "viewer"];

export default function Home() {
  const [key, setKey] = useState("");
  const [role, setRole] = useState("");
  const [tenant, setTenant] = useState("");
  const [productOwner, setProductOwner] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const [loginRequired, setLoginRequired] = useState(true);
  const [loginMode, setLoginMode] = useState<"login" | "setup" | "recover">(
    "login",
  );
  const [loginTenant, setLoginTenant] = useState("default");
  const [loginEmail, setLoginEmail] = useState("owner@relayops.local");
  const [loginName, setLoginName] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [bootstrapKey, setBootstrapKey] = useState("");
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [currentUser, setCurrentUser] = useState<AuthAccount | null>(null);
  const [browserSessions, setBrowserSessions] = useState<BrowserSession[]>([]);
  const [loginAccounts, setLoginAccounts] = useState<AuthAccount[]>([]);
  const [accountRole, setAccountRole] = useState("responder");
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState("");
  const refreshLock = useRef(false);
  const [rows, setRows] = useState<Incident[]>([]);
  const [totalIncidents, setTotalIncidents] = useState(0);
  const [matchingIncidents, setMatchingIncidents] = useState(0);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [navPosition, setNavPosition] = useState<
    "left" | "right" | "top" | "bottom"
  >("left");
  const [navActive, setNavActive] = useState("incidents");
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [analytics, setAnalytics] = useState<AnalyticsCounts | null>(null);
  const [chartPoints, setChartPoints] = useState<ChartPoint[]>([]);
  const [payloadFields, setPayloadFields] = useState<PayloadField[]>([]);
  const [connectorPicker, setConnectorPicker] = useState(false);
  const [connectors, setConnectors] = useState<ConnectorDefinition[]>([]);
  const [integrations, setIntegrations] = useState<TenantIntegration[]>([]);
  const [integrationModal, setIntegrationModal] = useState(false);
  const [editingConnector, setEditingConnector] =
    useState<ConnectorDefinition | null>(null);
  const [editingIntegration, setEditingIntegration] =
    useState<TenantIntegration | null>(null);
  const [page, setPage] = useState<
    | "incidents"
    | "users"
    | "policies"
    | "schedules"
    | "deliveries"
    | "integrations"
    | "tenants"
    | "analysis"
    | "account"
  >("incidents");
  const [users, setUsers] = useState<NotifyUser[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [schedules, setSchedules] = useState<OnCallSchedule[]>([]);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleTimezone, setScheduleTimezone] = useState("UTC");
  const [scheduleInterval, setScheduleInterval] = useState(480);
  const [scheduleStartsAt, setScheduleStartsAt] = useState(
    localDateTime(new Date().toISOString()),
  );
  const [scheduleMembers, setScheduleMembers] = useState("");
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(
    null,
  );
  const [tenants, setTenants] = useState<TenantRecord[]>([]);
  const [tenantSecret, setTenantSecret] = useState("");
  const [tenantMenu, setTenantMenu] = useState<TenantMenu | null>(null);
  const [managedTenant, setManagedTenant] = useState<TenantRecord | null>(null);
  const [managedTenantKeys, setManagedTenantKeys] = useState<ApiKey[]>([]);
  const [managedTenantSecret, setManagedTenantSecret] = useState("");
  const [managedExpiryDrafts, setManagedExpiryDrafts] = useState<
    Record<string, string>
  >({});
  const [incidentMenu, setIncidentMenu] = useState<IncidentMenu | null>(null);
  const [userModal, setUserModal] = useState(false);
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [groupDraftName, setGroupDraftName] = useState("");
  const [policyModal, setPolicyModal] = useState(false);
  const [draftSteps, setDraftSteps] = useState([
    { delay_minutes: 0, target_type: "team", target: "" },
  ]);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [newKeyExpiry, setNewKeyExpiry] = useState("");
  const [keyExpiryDrafts, setKeyExpiryDrafts] = useState<
    Record<string, string>
  >({});
  const [query, setQuery] = useState("");
  const [queryInput, setQueryInput] = useState("");
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("all");
  const [modal, setModal] = useState<"incident" | "test" | null>(null);
  const [settings, setSettings] = useState(false);
  const [access, setAccess] = useState(false);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState("");
  const [secret, setSecret] = useState("");
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRole, setNewKeyRole] = useState("integration");
  const request = useCallback(
    async (path: string, opts: RequestInit = {}, credential = key) => {
      const headers = new Headers(opts.headers);
      if (credential) headers.set("Authorization", `Bearer ${credential}`);
      else headers.delete("Authorization");
      headers.set("Content-Type", "application/json");
      const res = await fetch(`/backend${path}`, {
        ...opts,
        headers,
        credentials: "same-origin",
      });
      if (!res.ok) {
        if (res.status === 401) {
          setCurrentUser(null);
          setLoginRequired(true);
        }
        let message = `Request failed (${res.status})`;
        try {
          message = (await res.json()).error || message;
        } catch {}
        throw new Error(message);
      }
      return res.status === 204 ? null : res.json();
    },
    [key],
  );
  const ping = (s: string) => {
    setToast(s);
    window.setTimeout(() => setToast(""), 3000);
  };
  const refresh = useCallback(async () => {
    if (refreshLock.current) return;
    refreshLock.current = true;
    setRefreshing(true);
    try {
      if (!key) {
        const me = await request("/v1/auth/me", { cache: "no-store" });
        setCurrentUser(me.user);
        setRole(me.user.role);
        setTenant(`${me.tenant.name} · ${me.tenant.slug}`);
        setLoginRequired(false);
      }
      const incidentPath = query.trim()
        ? `/v1/incidents?search=${encodeURIComponent(query.trim())}`
        : "/v1/incidents";
      const inc = await request(incidentPath, { cache: "no-store" });
      setRows(inc.incidents || []);
      setTotalIncidents(inc.total_incidents ?? (inc.incidents || []).length);
      setMatchingIncidents(
        inc.matching_incidents ?? (inc.incidents || []).length,
      );
      setLastUpdated(
        new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      );
      const [who, pol] = await Promise.allSettled([
        request("/v1/tenant", { cache: "no-store" }),
        request("/v1/escalation-policies", { cache: "no-store" }),
      ]);
      if (who.status === "fulfilled") {
        setRole(who.value.role);
        setProductOwner(!!who.value.is_product_owner);
        setTenant(`${who.value.tenant.name} · ${who.value.tenant.slug}`);
      }
      if (pol.status === "fulfilled") setPolicies(pol.value.policies || []);
    } catch (e) {
      if (!key) {
        setLoginRequired(true);
      } else ping(`Could not refresh incidents: ${(e as Error).message}`);
    } finally {
      refreshLock.current = false;
      setRefreshing(false);
    }
  }, [key, query, request]);
  useEffect(() => {
    const stored = localStorage.getItem("relayops.key") || "";
    if (stored) {
      setKey(stored);
      setLoginRequired(false);
    } else {
      refresh().finally(() => setAuthReady(true));
    }
    const saved = localStorage.getItem("relayops.navPosition");
    if (
      saved === "left" ||
      saved === "right" ||
      saved === "top" ||
      saved === "bottom"
    )
      setNavPosition(saved);
    setNavCollapsed(localStorage.getItem("relayops.navCollapsed") === "true");
    if (stored) setAuthReady(true);
  }, [refresh]);
  useEffect(() => {
    if (!loginRequired) {
      refresh();
      const t = window.setInterval(refresh, 45000);
      return () => window.clearInterval(t);
    }
  }, [loginRequired, refresh]);
  const canCreate = ["owner", "admin", "responder", "integration"].includes(
      role,
    ),
    canRespond = ["owner", "admin", "responder"].includes(role),
    canManage = ["owner", "admin"].includes(role);
  const [summaryFilter, setSummaryFilter] = useState<
    "open" | "critical" | "acknowledged" | "resolvedToday" | "total" | null
  >(null);
  useEffect(() => {
    const timer = window.setTimeout(() => setQuery(queryInput), 160);
    return () => window.clearTimeout(timer);
  }, [queryInput]);
  const groupChoices = useMemo(
    () =>
      Array.from(
        new Set(
          users.flatMap((u) =>
            [u.team, ...(u.groups || [])].map((g) => g.trim()).filter(Boolean),
          ),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [users],
  );
  const applySummaryFilter = (
    filter: "open" | "critical" | "acknowledged" | "resolvedToday" | "total",
  ) => {
    setSummaryFilter(filter);
    setPage("incidents");
    setNavActive("incidents");
    setQuery("");
    setQueryInput("");
    setStatus(
      filter === "total"
        ? "all"
        : filter === "acknowledged"
          ? "acknowledged"
          : filter === "resolvedToday"
            ? "resolved"
            : "open",
    );
    setSeverity(filter === "critical" ? "critical" : "all");
  };
  const visible = useMemo(
    () =>
      rows.filter((x) => {
        const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
        const searchable = [
          x.id,
          x.incident_number,
          x.title,
          x.description,
          x.severity,
          x.status,
          x.source,
          x.service,
          x.dedup_key,
          x.assignee || "",
        ]
          .join(" ")
          .toLowerCase();
        return (
          (status === "all" ||
            (status === "open"
              ? x.status !== "resolved"
              : x.status === status)) &&
          (severity === "all" || x.severity === severity) &&
          (summaryFilter !== "resolvedToday" ||
            (x.status === "resolved" &&
              new Date(x.updated_at).toDateString() ===
                new Date().toDateString())) &&
          terms.every((term) => searchable.includes(term))
        );
      }),
    [rows, status, severity, query, summaryFilter],
  );
  const choose = async (x: Incident) => {
    setSelected(x);
    try {
      const r = await request(`/v1/incidents/${x.id}/events`);
      setEvents(r.events || []);
    } catch {
      setEvents([]);
    }
  };
  const saveSettings = () => {
    localStorage.setItem("relayops.key", key);
    setSettings(false);
    ping("API key saved on this device");
    refresh();
  };
  const submitLogin = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      const r = await request(
        "/v1/auth/login",
        {
          method: "POST",
          body: JSON.stringify({
            tenant_slug: loginTenant,
            email: loginEmail,
            password: loginPassword,
          }),
        },
        "",
      );
      localStorage.removeItem("relayops.key");
      setKey("");
      setCurrentUser(r.user);
      setRole(r.user.role);
      setProductOwner(!!r.user.is_product_owner);
      setTenant(`${r.tenant.name} · ${r.tenant.slug}`);
      setLoginPassword("");
      setLoginRequired(false);
      setAuthReady(true);
    } catch (err) {
      setAuthError((err as Error).message);
    } finally {
      setAuthBusy(false);
    }
  };
  const submitSetup = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      const r = await request(
        "/v1/auth/setup",
        {
          method: "POST",
          body: JSON.stringify({
            email: loginEmail,
            display_name: loginName,
            password: loginPassword,
            role: "owner",
          }),
        },
        bootstrapKey,
      );
      localStorage.removeItem("relayops.key");
      setKey("");
      setCurrentUser(r.user);
      setRole(r.user.role);
      setProductOwner(!!r.user.is_product_owner);
      setBootstrapKey("");
      setLoginPassword("");
      setLoginRequired(false);
      setAuthReady(true);
    } catch (err) {
      setAuthError((err as Error).message);
    } finally {
      setAuthBusy(false);
    }
  };
  const submitRecovery = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      await request(
        "/v1/auth/recover",
        {
          method: "POST",
          body: JSON.stringify({ email: loginEmail, password: loginPassword }),
        },
        bootstrapKey,
      );
      setBootstrapKey("");
      setLoginPassword("");
      setLoginMode("login");
      setAuthError(
        "If the account exists in this tenant, its password was reset and active sessions were revoked. Sign in with the new password.",
      );
    } catch (err) {
      const message = (err as Error).message;
      setAuthError(
        message.includes("authentication required")
          ? "Recovery needs the active tenant owner API key, not your account password. For the default tenant, use API_KEY from your .env file. Other tenants need their current owner key."
          : message.includes("cannot perform")
            ? "This API key does not have the owner role. Use the active tenant owner API key."
            : message,
      );
    } finally {
      setAuthBusy(false);
    }
  };
  const openAccountPage = async () => {
    setNavActive("account");
    setPage("account");
    try {
      const [me, sessions] = await Promise.all([
        request("/v1/auth/me"),
        request("/v1/auth/sessions"),
      ]);
      setCurrentUser(me.user);
      setBrowserSessions(sessions.sessions || []);
      if (["owner", "admin"].includes(me.user.role)) {
        const accounts = await request("/v1/auth/accounts");
        setLoginAccounts(accounts.accounts || []);
      }
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const createLoginAccount = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    try {
      await request("/v1/auth/accounts", {
        method: "POST",
        body: JSON.stringify({
          display_name: String(f.get("display_name")),
          email: String(f.get("email")),
          password: String(f.get("password")),
          role: accountRole,
        }),
      });
      const r = await request("/v1/auth/accounts");
      setLoginAccounts(r.accounts || []);
      form.reset();
      ping("Login account created");
    } catch (err) {
      ping((err as Error).message);
    }
  };
  const revokeBrowserSession = async (id: string) => {
    try {
      await request(`/v1/auth/sessions/${id}`, { method: "DELETE" });
      if (browserSessions.find((s) => s.id === id)?.current) {
        setLoginRequired(true);
        setCurrentUser(null);
      } else setBrowserSessions(browserSessions.filter((s) => s.id !== id));
      ping("Session revoked");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const signOut = async () => {
    try {
      await request("/v1/auth/logout", { method: "POST" }, "");
    } catch {}
    localStorage.removeItem("relayops.key");
    setKey("");
    setCurrentUser(null);
    setRole("");
    setProductOwner(false);
    setTenant("");
    setLoginRequired(true);
    setLoginMode("login");
    setPage("incidents");
    setNavActive("incidents");
  };
  const submitIncident = async (
    e: FormEvent<HTMLFormElement>,
    isTest: boolean,
  ) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const title = String(f.get("title") || "").trim(),
      policy = String(f.get("policy") || "");
    if (isTest && !policy) {
      ping("Select an escalation policy first");
      return;
    }
    if (
      isTest &&
      !window.confirm(
        "Create a real test incident? Active targets in this policy can receive email or webhook notifications.",
      )
    )
      return;
    const dedup = isTest
      ? `relayops-test-${crypto.randomUUID()}`
      : String(f.get("dedup_key") || "").trim();
    setBusy(true);
    try {
      const result = await request("/v1/alerts", {
        method: "POST",
        body: JSON.stringify({
          dedup_key: dedup,
          title,
          description: String(f.get("description") || ""),
          severity: String(f.get("severity") || "warning"),
          source: isTest
            ? "relayops-test-flow"
            : String(f.get("source") || "manual"),
          service: String(f.get("service") || ""),
          labels: isTest ? { relayops_test: true } : {},
          metadata: isTest
            ? { test: true, created_from: "nextjs-dashboard" }
            : {},
          escalation_policy_id: policy || null,
        }),
      });
      setModal(null);
      ping(`Created ${result.incident.incident_number}; escalation is queued`);
      await refresh();
      await choose(result.incident);
    } catch (err) {
      ping((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const actOnIncident = async (
    incident: Incident,
    action: "acknowledge" | "resolve",
  ) => {
    const note = window.prompt(
      `${action === "resolve" ? "Resolution" : "Acknowledgement"} note (optional):`,
      "",
    );
    if (note === null) return;
    setIncidentMenu(null);
    try {
      await request(`/v1/incidents/${incident.id}/${action}`, {
        method: "POST",
        body: JSON.stringify({ actor: "operator", note }),
      });
      ping(
        action === "resolve" ? "Incident resolved" : "Incident acknowledged",
      );
      await refresh();
      await choose({
        ...incident,
        status: action === "resolve" ? "resolved" : "acknowledged",
        updated_at: new Date().toISOString(),
      });
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const act = async (action: "acknowledge" | "resolve") => {
    if (selected) await actOnIncident(selected, action);
  };
  const openAccess = async () => {
    setAccess(true);
    setSecret("");
    if (!canManage) return;
    try {
      const r = await request("/v1/api-keys");
      setKeys(r.api_keys || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const openUsers = async () => {
    setNavActive("users");
    setPage("users");
    if (!canManage) {
      ping("User and channel configuration requires owner or admin access");
      return;
    }
    try {
      const r = await request("/v1/notification-users");
      setUsers(r.users || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const openPolicies = async () => {
    setNavActive("policies");
    setPage("policies");
    if (!canManage) return;
    try {
      const [u, s] = await Promise.all([
        request("/v1/notification-users"),
        request("/v1/schedules"),
      ]);
      setUsers(u.users || []);
      setSchedules(s.schedules || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const openSchedules = async () => {
    if (!canManage) {
      ping("On-call schedules require owner or admin access");
      return;
    }
    setNavActive("schedules");
    setPage("schedules");
    try {
      const r = await request("/v1/schedules");
      setSchedules(r.schedules || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const clearScheduleDraft = () => {
    setEditingScheduleId(null);
    setScheduleName("");
    setScheduleTimezone("UTC");
    setScheduleInterval(480);
    setScheduleStartsAt(localDateTime(new Date().toISOString()));
    setScheduleMembers("");
  };
  const editSchedule = (s: OnCallSchedule) => {
    setEditingScheduleId(s.id);
    setScheduleName(s.name);
    setScheduleTimezone(s.timezone);
    setScheduleInterval(s.rotation_interval_minutes);
    setScheduleStartsAt(localDateTime(s.rotation_starts_at));
    setScheduleMembers(s.members.join(", "));
  };
  const saveSchedule = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const starts = new Date(scheduleStartsAt);
      if (Number.isNaN(starts.getTime()))
        throw new Error("Choose a valid rotation start time");
      const body = {
        name: scheduleName,
        timezone: scheduleTimezone,
        rotation_interval_minutes: Number(scheduleInterval),
        rotation_starts_at: starts.toISOString(),
        members: scheduleMembers
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
      };
      const result = await request(
        editingScheduleId
          ? `/v1/schedules/${editingScheduleId}`
          : "/v1/schedules",
        {
          method: editingScheduleId ? "PUT" : "POST",
          body: JSON.stringify(body),
        },
      );
      setSchedules((current) =>
        editingScheduleId
          ? current.map((s) =>
              s.id === editingScheduleId ? result.schedule : s,
            )
          : [...current, result.schedule].sort((a, b) =>
              a.name.localeCompare(b.name),
            ),
      );
      clearScheduleDraft();
      ping("On-call schedule saved");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const removeSchedule = async (id: string) => {
    if (
      !window.confirm(
        "Delete this on-call schedule? Escalation steps using it will retry until updated.",
      )
    )
      return;
    try {
      await request(`/v1/schedules/${id}`, { method: "DELETE" });
      setSchedules(schedules.filter((s) => s.id !== id));
      if (editingScheduleId === id) clearScheduleDraft();
      ping("Schedule deleted");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const openDeliveries = async () => {
    setNavActive("deliveries");
    setPage("deliveries");
    if (!canManage) {
      ping("Delivery queue requires owner or admin access");
      return;
    }
    try {
      const r = await request("/v1/notification-deliveries");
      setDeliveries(r.deliveries || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const openTenants = async () => {
    setNavActive("tenants");
    setPage("tenants");
    setTenantSecret("");
    try {
      const who = await request("/v1/tenant");
      setProductOwner(!!who.is_product_owner);
      const r = await request("/v1/tenants");
      setTenants(r.tenants || []);
    } catch {
      ping("Tenant view requires owner access");
    }
  };
  const loadAnalytics = useCallback(async () => {
    if (!key) return;
    try {
      const r: AnalyticsCounts = await request("/v1/analytics/incidents", {
        cache: "no-store",
      });
      setAnalytics(r);
      setChartPoints((points) =>
        [...points, { at: Date.now(), total: r.total }].slice(-60),
      );
    } catch (e) {
      ping(`Could not load analysis: ${(e as Error).message}`);
    }
  }, [key, query, request]);
  useEffect(() => {
    if (page !== "analysis" || !key) return;
    loadAnalytics();
    const timer = window.setInterval(loadAnalytics, 10000);
    return () => window.clearInterval(timer);
  }, [page, key, loadAnalytics]);
  const openIntegrations = async () => {
    setNavActive("integrations");
    setPage("integrations");
    if (!canManage) {
      ping("Integration configuration requires owner or admin access");
      return;
    }
    try {
      const [catalog, saved] = await Promise.all([
        request("/v1/integration-catalog"),
        request("/v1/integrations"),
      ]);
      setConnectors(catalog.connectors || []);
      setIntegrations(saved.integrations || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const saveUser = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      await request("/v1/notification-users", {
        method: "POST",
        body: JSON.stringify({
          handle: String(f.get("handle")),
          team: String(f.get("team")),
          email: String(f.get("email") || ""),
          webhook: String(f.get("webhook") || ""),
          groups: Array.from(
            new Set([
              ...selectedGroups,
              ...String(f.get("team") || "")
                .split(",")
                .map((g) => g.trim())
                .filter(Boolean),
            ]),
          ),
        }),
      });
      const r = await request("/v1/notification-users");
      setUsers(r.users || []);
      setUserModal(false);
      setSelectedGroups([]);
      setGroupDraftName("");
      ping("Responder, channels, and groups saved");
    } catch (err) {
      ping((err as Error).message);
    }
  };
  const savePolicy = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      const result = await request("/v1/escalation-policies", {
        method: "POST",
        body: JSON.stringify({
          name: String(f.get("name")),
          description: String(f.get("description") || ""),
          timezone: String(f.get("timezone")),
          repeat_count: Number(f.get("repeat_count") || 0),
          repeat_every_minutes: Number(f.get("repeat_every_minutes") || 30),
          steps: draftSteps,
        }),
      });
      setPolicies([...policies, result.policy]);
      setPolicyModal(false);
      setDraftSteps([{ delay_minutes: 0, target_type: "team", target: "" }]);
      ping("Escalation policy saved");
    } catch (err) {
      ping((err as Error).message);
    }
  };
  const retryDelivery = async (id: string) => {
    try {
      await request(`/v1/notification-deliveries/${id}/retry`, {
        method: "POST",
      });
      const r = await request("/v1/notification-deliveries");
      setDeliveries(r.deliveries || []);
      ping("Delivery queued for retry");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const createTenant = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      const r = await request("/v1/tenants", {
        method: "POST",
        body: JSON.stringify({
          name: String(f.get("name")),
          slug: String(f.get("slug")),
        }),
      });
      setTenantSecret(r.api_key);
      const list = await request("/v1/tenants");
      setTenants(list.tenants || []);
      ping("Tenant created; save its key now");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const beginIntegration = (
    connector: ConnectorDefinition,
    record: TenantIntegration | null = null,
  ) => {
    setEditingConnector(connector);
    setEditingIntegration(record);
    const saved = record?.configuration?.payload_fields;
    setPayloadFields(Array.isArray(saved) ? (saved as PayloadField[]) : []);
    setIntegrationModal(true);
  };
  const chooseConnector = (connector: ConnectorDefinition) => {
    setConnectorPicker(false);
    beginIntegration(connector);
  };
  const saveIntegration = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editingConnector) return;
    const f = new FormData(e.currentTarget);
    const configuration: Record<string, unknown> = {};
    for (const field of editingConnector.fields) {
      if (field === "credential_reference") continue;
      const value = String(f.get(field) || "").trim();
      if (value) configuration[field] = value;
    }
    if (payloadFields.length) configuration.payload_fields = payloadFields;
    const body = {
      connector_key: editingConnector.key,
      name: String(f.get("name") || ""),
      enabled: f.get("enabled") === "on",
      configuration,
      credential_reference:
        String(f.get("credential_reference") || "").trim() || null,
    };
    try {
      const path = editingIntegration
        ? `/v1/integrations/${editingIntegration.id}`
        : "/v1/integrations";
      await request(path, {
        method: editingIntegration ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      const result = await request("/v1/integrations");
      setIntegrations(result.integrations || []);
      setIntegrationModal(false);
      setEditingIntegration(null);
      ping("Integration configuration saved");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const validateIntegration = async (id: string) => {
    try {
      const r = await request(`/v1/integrations/${id}/validate`, {
        method: "POST",
      });
      const list = await request("/v1/integrations");
      setIntegrations(list.integrations || []);
      ping(
        r.provider_adapter_available
          ? "Configuration validated"
          : "Fields valid; provider adapter is not installed",
      );
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const removeIntegration = async (id: string) => {
    if (!window.confirm("Remove this integration configuration?")) return;
    try {
      await request(`/v1/integrations/${id}`, { method: "DELETE" });
      setIntegrations(integrations.filter((x) => x.id !== id));
      ping("Integration removed");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const createKey = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await request("/v1/api-keys", {
        method: "POST",
        body: JSON.stringify({
          name: newKeyName,
          role: newKeyRole,
          expires_at: newKeyExpiry
            ? new Date(newKeyExpiry).toISOString()
            : null,
        }),
      });
      setSecret(r.secret);
      setNewKeyName("");
      setNewKeyExpiry("");
      const list = await request("/v1/api-keys");
      setKeys(list.api_keys || []);
    } catch (err) {
      ping((err as Error).message);
    }
  };
  const revoke = async (id: string) => {
    if (
      !window.confirm("Revoke this key? Any system using it will lose access.")
    )
      return;
    try {
      await request(`/v1/api-keys/${id}`, { method: "DELETE" });
      setKeys(keys.filter((k) => k.id !== id));
      ping("API key revoked");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const saveKeyExpiry = async (id: string) => {
    try {
      const draft = keyExpiryDrafts[id] ?? "";
      const r = await request(`/v1/api-keys/${id}`, {
        method: "PUT",
        body: JSON.stringify({
          expires_at: draft ? new Date(draft).toISOString() : null,
        }),
      });
      setKeys(keys.map((k) => (k.id === id ? r.api_key : k)));
      ping(draft ? "API key expiration updated" : "API key expiration removed");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const rotateKey = async (id: string) => {
    if (
      !window.confirm(
        "Replace this API key now? The old key will stop working immediately.",
      )
    )
      return;
    try {
      const r = await request(`/v1/api-keys/${id}/rotate`, { method: "POST" });
      setSecret(r.secret);
      setKeys(keys.map((k) => (k.id === id ? r.api_key : k)));
      if (r.rotated_current_key) {
        setKey(r.secret);
        localStorage.setItem("relayops.key", r.secret);
      }
      ping("API key replaced; copy the new secret now");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const loadManagedTenantKeys = async (target: TenantRecord) => {
    setManagedTenant(target);
    setTenantMenu(null);
    setManagedTenantSecret("");
    setManagedExpiryDrafts({});
    try {
      const r = await request(`/v1/tenants/${target.id}/api-keys`);
      setManagedTenantKeys(r.api_keys || []);
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const refreshManagedTenantKeys = async () => {
    if (!managedTenant) return;
    const r = await request(`/v1/tenants/${managedTenant.id}/api-keys`);
    setManagedTenantKeys(r.api_keys || []);
  };
  const saveManagedExpiration = async (id: string) => {
    if (!managedTenant) return;
    try {
      const draft = managedExpiryDrafts[id] ?? "";
      const r = await request(
        `/v1/tenants/${managedTenant.id}/api-keys/${id}`,
        {
          method: "PUT",
          body: JSON.stringify({
            expires_at: draft ? new Date(draft).toISOString() : null,
          }),
        },
      );
      setManagedTenantKeys(
        managedTenantKeys.map((k) => (k.id === id ? r.api_key : k)),
      );
      ping(
        draft
          ? "Tenant API key expiration updated"
          : "Tenant API key expiration removed",
      );
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const rotateManagedKey = async (id: string) => {
    if (
      !managedTenant ||
      !window.confirm(
        "Replace this tenant API key? Its old value will stop working immediately.",
      )
    )
      return;
    try {
      const r = await request(
        `/v1/tenants/${managedTenant.id}/api-keys/${id}/rotate`,
        { method: "POST" },
      );
      setManagedTenantSecret(r.secret);
      await refreshManagedTenantKeys();
      ping("Tenant key replaced; copy the new secret now");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const revokeManagedKey = async (id: string) => {
    if (
      !managedTenant ||
      !window.confirm(
        "Revoke this tenant API key now? Services using it will lose access.",
      )
    )
      return;
    try {
      await request(`/v1/tenants/${managedTenant.id}/api-keys/${id}`, {
        method: "DELETE",
      });
      await refreshManagedTenantKeys();
      ping("Tenant API key revoked");
    } catch (e) {
      ping((e as Error).message);
    }
  };
  const chartGeometry = useMemo(() => {
    const width = 720,
      height = 250,
      pad = 34,
      max = Math.max(1, ...chartPoints.map((p) => p.total));
    const coords = chartPoints.map((p, i) => ({
      x:
        chartPoints.length < 2
          ? pad + (width - pad * 2) / 2
          : pad + (i * (width - pad * 2)) / (chartPoints.length - 1),
      y: height - pad - (p.total / max) * (height - pad * 2),
    }));
    return {
      width,
      height,
      pad,
      coords,
      path: coords.map((p, i) => `${i ? "L" : "M"}${p.x},${p.y}`).join(" "),
      max,
    };
  }, [chartPoints]);
  const authModeForm =
    loginMode === "recover" ? (
      <form className="auth-form" onSubmit={submitRecovery}>
        <p>
          Reset an existing tenant login with its owner API key. Active sessions
          for that account will be revoked.
        </p>
        <label className="field">
          Tenant owner API key
          <input
            required
            type="password"
            value={bootstrapKey}
            onChange={(e) => setBootstrapKey(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          Account email
          <input
            required
            type="email"
            value={loginEmail}
            onChange={(e) => setLoginEmail(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="field">
          New password (12 characters minimum)
          <input
            required
            type="password"
            minLength={12}
            maxLength={1024}
            value={loginPassword}
            onChange={(e) => setLoginPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        {authError && <div className="warning">{authError}</div>}
        <button className="btn primary" disabled={authBusy}>
          {authBusy ? "Resetting…" : "Reset password"}
        </button>
      </form>
    ) : loginMode === "login" ? (
      <form className="auth-form" onSubmit={submitLogin}>
        <label className="field">
          Tenant slug
          <input
            required
            value={loginTenant}
            onChange={(e) => setLoginTenant(e.target.value)}
            placeholder="acme"
            autoComplete="organization"
          />
        </label>
        <label className="field">
          Email
          <input
            required
            type="email"
            value={loginEmail}
            onChange={(e) => setLoginEmail(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="field">
          Password
          <input
            required
            type="password"
            value={loginPassword}
            onChange={(e) => setLoginPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {authError && <div className="warning">{authError}</div>}
        <button className="btn primary" disabled={authBusy}>
          {authBusy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    ) : (
      <form className="auth-form" onSubmit={submitSetup}>
        <p>
          Create the tenant’s first owner login. The tenant API key is used once
          to authorize setup and is not saved.
        </p>
        <label className="field">
          Tenant API key
          <input
            required
            type="password"
            value={bootstrapKey}
            onChange={(e) => setBootstrapKey(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          Display name
          <input
            required
            maxLength={120}
            value={loginName}
            onChange={(e) => setLoginName(e.target.value)}
          />
        </label>
        <label className="field">
          Email
          <input
            required
            type="email"
            value={loginEmail}
            onChange={(e) => setLoginEmail(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="field">
          Password (12 characters minimum)
          <input
            required
            type="password"
            minLength={12}
            maxLength={1024}
            value={loginPassword}
            onChange={(e) => setLoginPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        {authError && <div className="warning">{authError}</div>}
        <button className="btn primary" disabled={authBusy}>
          {authBusy ? "Creating account…" : "Create owner login"}
        </button>
      </form>
    );
  if (!authReady)
    return (
      <div className="auth-screen">
        <section className="auth-card">
          <div className="logo">R</div>
          <h1>RelayOps</h1>
          <p>Checking your sign-in session…</p>
        </section>
      </div>
    );
  if (loginRequired)
    return (
      <div className="auth-screen">
        <section className="auth-card">
          <div className="logo">R</div>
          <h1>RelayOps</h1>
          <p>Sign in to your tenant workspace.</p>
          <div className="auth-tabs">
            <button
              type="button"
              className={loginMode === "login" ? "selected" : ""}
              onClick={() => {
                setLoginMode("login");
                setAuthError("");
              }}
            >
              Sign in
            </button>
            <button
              type="button"
              className={loginMode === "setup" ? "selected" : ""}
              onClick={() => {
                setLoginMode("setup");
                setAuthError("");
              }}
            >
              First-time setup
            </button>
            <button
              type="button"
              className={loginMode === "recover" ? "selected" : ""}
              onClick={() => {
                setLoginMode("recover");
                setAuthError("");
              }}
            >
              Recover access
            </button>
          </div>
          {authModeForm}
        </section>
      </div>
    );
  const active = rows.filter((x) => x.status !== "resolved"),
    critical = active.filter((x) => x.severity === "critical").length,
    acked = active.filter((x) => x.status === "acknowledged").length,
    resolved = rows.filter(
      (x) =>
        x.status === "resolved" &&
        new Date(x.updated_at).toDateString() === new Date().toDateString(),
    ).length;
  return (
    <div
      className={`appframe nav-${navPosition} ${navCollapsed ? "nav-collapsed" : ""}`}
    >
      <nav className="navigation" aria-label="Main navigation">
        <div className="navbrand">
          <span className="logo">R</span>
          <strong>RelayOps</strong>
          <button
            className="navtoggle"
            title={navCollapsed ? "Expand navigation" : "Collapse navigation"}
            aria-label={
              navCollapsed ? "Expand navigation" : "Collapse navigation"
            }
            onClick={() => {
              const next = !navCollapsed;
              setNavCollapsed(next);
              localStorage.setItem("relayops.navCollapsed", String(next));
            }}
          >
            {navCollapsed ? "»" : "«"}
          </button>
        </div>
        <button
          className={`navitem ${navActive === "incidents" ? "active" : ""}`}
          aria-label="Incident desk"
          title="Incident desk"
          onClick={() => {
            setNavActive("incidents");
            setPage("incidents");
          }}
        >
          ▦ <span>Incident desk</span>
        </button>
        <button
          className="navitem"
          aria-label="New incident"
          title="New incident"
          disabled={!canCreate}
          onClick={() => {
            setNavActive("create");
            setModal("incident");
          }}
        >
          ＋ <span>New incident</span>
        </button>
        <button
          className="navitem"
          aria-label="Run test flow"
          title="Run test flow"
          disabled={!canCreate}
          onClick={() => {
            setNavActive("test");
            setModal("test");
          }}
        >
          ⇄ <span>Run test flow</span>
        </button>
        <button
          className={`navitem ${navActive === "analysis" ? "active" : ""}`}
          title="Analysis"
          onClick={() => {
            setNavActive("analysis");
            setPage("analysis");
          }}
        >
          ▤ <span>Analysis</span>
        </button>
        <button
          className={`navitem ${navActive === "users" ? "active" : ""}`}
          title="Users & channels"
          onClick={openUsers}
        >
          ♙ <span>Users & channels</span>
        </button>
        {canManage && (
          <button
            className={`navitem ${navActive === "schedules" ? "active" : ""}`}
            title="On-call schedules"
            onClick={openSchedules}
          >
            ◷ <span>On-call schedules</span>
          </button>
        )}
        <button
          className={`navitem ${navActive === "policies" ? "active" : ""}`}
          title="Escalation policies"
          onClick={openPolicies}
        >
          ⇧ <span>Escalation policies</span>
        </button>
        <button
          className={`navitem ${navActive === "deliveries" ? "active" : ""}`}
          title="Notification deliveries"
          onClick={openDeliveries}
        >
          ↗ <span>Notification deliveries</span>
        </button>
        <button
          className={`navitem ${navActive === "integrations" ? "active" : ""}`}
          title="Integrations"
          onClick={openIntegrations}
        >
          ◈ <span>Integrations</span>
        </button>
        {role === "owner" && (
          <button
            className={`navitem ${navActive === "tenants" ? "active" : ""}`}
            title="Tenants"
            onClick={openTenants}
          >
            ▤ <span>Tenants</span>
          </button>
        )}
        {currentUser && !productOwner && (
          <button
            className={`navitem ${navActive === "account" ? "active" : ""}`}
            title="Account & sessions"
            onClick={openAccountPage}
          >
            ♙ <span>Account & sessions</span>
          </button>
        )}
        <button
          className="navitem"
          title="Access & roles"
          onClick={() => {
            setNavActive("access");
            openAccess();
          }}
        >
          ⚿ <span>Access & roles</span>
        </button>
        <button
          className="navitem"
          title="Settings"
          onClick={() => {
            setNavActive("settings");
            setSettings(true);
          }}
        >
          ⚙ <span>Settings</span>
        </button>
        {role && (
          <button className="navitem" title="Sign out" onClick={signOut}>
            ⇥ <span>Sign out</span>
          </button>
        )}
      </nav>
      <main className="shell">
        <header className="top">
          <div className="brand">
            <div className="logo">R</div>
            <div>
              <h1>RelayOps</h1>
              <p>{tenant || "Incident response workspace"}</p>
            </div>
          </div>
          <form
            className="global-search"
            onSubmit={(e) => {
              e.preventDefault();
              setPage("incidents");
              setNavActive("incidents");
              setSummaryFilter(null);
              setStatus("all");
              setSeverity("all");
              setQuery(queryInput);
            }}
          >
            <span aria-hidden="true">⌕</span>
            <input
              aria-label="Search incidents by incident key"
              placeholder="Search by incident key or title"
              value={queryInput}
              onChange={(e) => {
                setQueryInput(e.target.value);
                setSummaryFilter(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  setQueryInput("");
                  setQuery("");
                }
              }}
            />
            {queryInput && (
              <button
                type="button"
                aria-label="Clear incident search"
                onClick={() => {
                  setQueryInput("");
                  setQuery("");
                  setPage("incidents");
                  setNavActive("incidents");
                  setStatus("all");
                  setSeverity("all");
                  setSummaryFilter(null);
                }}
              >
                ×
              </button>
            )}
            <button type="submit">Search</button>
          </form>
          <div className="actions">
            <span className={`conn`}>
              <i className={`dot ${role ? "ok" : "bad"}`} />
              {role ? `Connected · ${role}` : "Not connected"}
            </span>
          </div>
        </header>
        {page === "incidents" && (
          <>
            <section className="heading">
              <div>
                <h2>Incident desk</h2>
                <p>
                  Review alerts, respond, and confirm your notification flow.
                </p>
              </div>
              <div className="refresh-control">
                <span className="refresh-time">
                  {refreshing
                    ? "Refreshing…"
                    : lastUpdated
                      ? `Updated ${lastUpdated}`
                      : "Not refreshed yet"}
                </span>
                <button className="btn" disabled={refreshing} onClick={refresh}>
                  {refreshing ? "↻ Refreshing" : "↻ Refresh"}
                </button>
              </div>
            </section>
            <section className="stats">
              <button
                type="button"
                aria-pressed={summaryFilter === "total"}
                className={`stat stat-total ${summaryFilter === "total" ? "stat-selected" : ""}`}
                onClick={() => applySummaryFilter("total")}
              >
                <span>Total incidents / alerts</span>
                <strong>{totalIncidents}</strong>
                <small>All statuses · click to view all</small>
              </button>
              <div className="status-stats">
                <button
                  type="button"
                  aria-pressed={summaryFilter === "open"}
                  className={`stat ${summaryFilter === "open" ? "stat-selected" : ""}`}
                  onClick={() => applySummaryFilter("open")}
                >
                  <span>Open incidents</span>
                  <strong>{active.length}</strong>
                  <small>Need follow-up · click to filter</small>
                </button>
                <button
                  type="button"
                  aria-pressed={summaryFilter === "critical"}
                  className={`stat ${summaryFilter === "critical" ? "stat-selected" : ""}`}
                  onClick={() => applySummaryFilter("critical")}
                >
                  <span>Critical</span>
                  <strong className="critical">{critical}</strong>
                  <small>Highest urgency · click to filter</small>
                </button>
                <button
                  type="button"
                  aria-pressed={summaryFilter === "acknowledged"}
                  className={`stat ${summaryFilter === "acknowledged" ? "stat-selected" : ""}`}
                  onClick={() => applySummaryFilter("acknowledged")}
                >
                  <span>Acknowledged</span>
                  <strong className="ack">{acked}</strong>
                  <small>Being investigated · click to filter</small>
                </button>
                <button
                  type="button"
                  aria-pressed={summaryFilter === "resolvedToday"}
                  className={`stat ${summaryFilter === "resolvedToday" ? "stat-selected" : ""}`}
                  onClick={() => applySummaryFilter("resolvedToday")}
                >
                  <span>Resolved today</span>
                  <strong className="resolved">{resolved}</strong>
                  <small>Closed today · click to filter</small>
                </button>
              </div>
            </section>
            <section className="board">
              <div className="toolbar">
                <select
                  className="control"
                  value={status}
                  onChange={(e) => {
                    setStatus(e.target.value);
                    setSummaryFilter(null);
                  }}
                >
                  <option value="open">Open incidents</option>
                  <option value="all">All statuses</option>
                  <option value="triggered">Triggered</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="resolved">Resolved</option>
                </select>
                <select
                  className="control"
                  value={severity}
                  onChange={(e) => {
                    setSeverity(e.target.value);
                    setSummaryFilter(null);
                  }}
                >
                  <option value="all">All severity</option>
                  {["critical", "error", "warning", "info"].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </div>
              <div className="grid">
                <div className="list">
                  <div className="listhead">
                    <span>Incident</span>
                    <span>Severity</span>
                    <span>Updated</span>
                  </div>
                  {visible.length ? (
                    visible.slice(0, 500).map((x) => (
                      <div
                        key={x.id}
                        className={`incident ${selected?.id === x.id ? "selected" : ""}`}
                        onClick={() => choose(x)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setIncidentMenu({
                            incident: x,
                            x: e.clientX,
                            y: e.clientY,
                          });
                        }}
                      >
                        <div>
                          <div className="title">{x.title}</div>
                          <div className="sub">
                            {x.incident_number} ·{" "}
                            {x.service || x.source || x.dedup_key}
                          </div>
                        </div>
                        <span className={`badge ${x.severity}`}>
                          {x.severity}
                        </span>
                        <span className={`time status ${x.status}`}>
                          {pretty(x.updated_at)}
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="empty">
                      No incidents match these filters.
                    </div>
                  )}
                  <div className="pager">
                    <span>
                      {queryInput.trim()
                        ? `${matchingIncidents} matching incidents`
                        : `Showing ${Math.min(visible.length, 500)} of up to 500 latest incidents`}
                    </span>
                    <button className="btn" onClick={refresh}>
                      Refresh list
                    </button>
                  </div>
                </div>
                <aside className="detail">
                  {selected ? (
                    <>
                      <span className={`badge ${selected.severity}`}>
                        {selected.severity}
                      </span>
                      <h3>{selected.title}</h3>
                      <span className={`status ${selected.status}`}>
                        {selected.status}
                      </span>
                      <div className="row-actions" style={{ marginTop: 14 }}>
                        {canRespond &&
                          selected.status !== "acknowledged" &&
                          selected.status !== "resolved" && (
                            <button
                              className="btn primary"
                              onClick={() => act("acknowledge")}
                            >
                              Acknowledge
                            </button>
                          )}
                        {canRespond && selected.status !== "resolved" && (
                          <button
                            className="btn"
                            onClick={() => act("resolve")}
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                      <p className="description">
                        {selected.description || "No description provided."}
                      </p>
                      <dl className="kv">
                        <dt>Service</dt>
                        <dd>{selected.service || "—"}</dd>
                        <dt>Source</dt>
                        <dd>{selected.source || "—"}</dd>
                        <dt>Incident ID</dt>
                        <dd>{selected.incident_number}</dd>
                        <dt>Internal ID</dt>
                        <dd>{selected.id}</dd>
                        <dt>Dedup key</dt>
                        <dd>{selected.dedup_key}</dd>
                        <dt>Created</dt>
                        <dd>{pretty(selected.created_at)}</dd>
                      </dl>
                      <div className="timeline-title">Response timeline</div>
                      {events.map((a) => (
                        <div className="event" key={a.id}>
                          <strong>{a.kind.replace("_", " ")}</strong> ·{" "}
                          {a.actor}
                          {a.note ? ` — ${a.note}` : ""}
                          <time>{pretty(a.created_at)}</time>
                        </div>
                      ))}
                    </>
                  ) : (
                    <div className="empty">
                      Select an incident to view details and its response
                      timeline.
                    </div>
                  )}
                </aside>
              </div>
            </section>
          </>
        )}
        {page === "analysis" && (
          <section className="panel settings-page analysis-page">
            <div className="heading">
              <div>
                <h2>Incident analysis</h2>
                <p>
                  Tenant incident volume and ownership, refreshed every 10
                  seconds while this page is open.
                </p>
              </div>
              <div className="live-mark">
                <i /> LIVE · 10s
              </div>
            </div>
            <article className="chart-card">
              <div className="chart-heading">
                <div>
                  <strong>Total incidents</strong>
                  <small>
                    {analytics?.total ?? 0} incidents in this tenant
                  </small>
                </div>
                <span>
                  {chartPoints.length
                    ? `Last sample ${new Date(chartPoints[chartPoints.length - 1].at).toLocaleTimeString()}`
                    : "Waiting for first sample…"}
                </span>
              </div>
              <div className="chart-scroll">
                <svg
                  className="incident-chart"
                  viewBox={`0 0 ${chartGeometry.width} ${chartGeometry.height}`}
                  role="img"
                  aria-label="Total incidents sampled every ten seconds"
                >
                  <line
                    x1={chartGeometry.pad}
                    y1={chartGeometry.height - chartGeometry.pad}
                    x2={chartGeometry.width - chartGeometry.pad}
                    y2={chartGeometry.height - chartGeometry.pad}
                    className="chart-axis"
                  />
                  <line
                    x1={chartGeometry.pad}
                    y1={chartGeometry.pad}
                    x2={chartGeometry.pad}
                    y2={chartGeometry.height - chartGeometry.pad}
                    className="chart-axis"
                  />
                  <text x="4" y={chartGeometry.pad + 4} className="chart-label">
                    {chartGeometry.max}
                  </text>
                  <text
                    x="13"
                    y={chartGeometry.height - chartGeometry.pad}
                    className="chart-label"
                  >
                    0
                  </text>
                  {chartGeometry.coords.length > 1 && (
                    <path d={chartGeometry.path} className="chart-line" />
                  )}
                  {chartGeometry.coords.map((pt, i) => (
                    <circle
                      key={`${chartPoints[i].at}-${i}`}
                      cx={pt.x}
                      cy={pt.y}
                      r="3.5"
                      className="chart-dot"
                    >
                      <title>
                        {new Date(chartPoints[i].at).toLocaleTimeString()}:{" "}
                        {chartPoints[i].total} incidents
                      </title>
                    </circle>
                  ))}
                </svg>
              </div>
              <div className="chart-foot">
                <span>Older</span>
                <span>
                  Each point is a 10-second total snapshot · showing up to 10
                  minutes
                </span>
                <span>Now</span>
              </div>
            </article>
            <div className="analysis-groups">
              <section>
                <h3>Incidents by integration / source</h3>
                <p>
                  Grouped by the source value submitted when the incident was
                  created.
                </p>
                <div className="count-tiles">
                  {analytics ? (
                    analytics.by_integration.length ? (
                      analytics.by_integration.map(([label, count]) => (
                        <article className="count-tile" key={label}>
                          <small>{label}</small>
                          <strong>{count}</strong>
                          <span>incidents</span>
                        </article>
                      ))
                    ) : (
                      <div className="empty">No incidents recorded yet.</div>
                    )
                  ) : (
                    <div className="empty">Loading source counts…</div>
                  )}
                </div>
              </section>
              <section>
                <h3>Incidents by user</h3>
                <p>
                  Grouped by current assignee; unassigned incidents are shown
                  separately.
                </p>
                <div className="count-tiles">
                  {analytics ? (
                    analytics.by_user.length ? (
                      analytics.by_user.map(([label, count]) => (
                        <article className="count-tile" key={label}>
                          <small>{label}</small>
                          <strong>{count}</strong>
                          <span>incidents</span>
                        </article>
                      ))
                    ) : (
                      <div className="empty">No incidents recorded yet.</div>
                    )
                  ) : (
                    <div className="empty">Loading user counts…</div>
                  )}
                </div>
              </section>
            </div>
          </section>
        )}{" "}
        {page === "account" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Account & sessions</h2>
                <p>
                  {currentUser?.display_name} · {currentUser?.email} ·{" "}
                  {currentUser?.role}
                </p>
              </div>
            </div>
            <h3>Active sessions</h3>
            {browserSessions.length ? (
              browserSessions.map((x) => (
                <article className="accessrow" key={x.id}>
                  <div>
                    <strong>
                      {x.current ? "This session" : "Other session"}
                    </strong>
                    <small>
                      Last active {pretty(x.last_seen_at)} · Expires{" "}
                      {pretty(x.expires_at)} · {x.user_agent || "Browser"}
                    </small>
                  </div>
                  <button
                    className="btn danger"
                    onClick={() => revokeBrowserSession(x.id)}
                  >
                    Revoke
                  </button>
                </article>
              ))
            ) : (
              <div className="empty">No active browser sessions.</div>
            )}
            {canManage && (
              <>
                <h3>Login accounts</h3>
                <form onSubmit={createLoginAccount}>
                  <div className="form">
                    <label className="field">
                      Display name
                      <input name="display_name" required maxLength={120} />
                    </label>
                    <label className="field">
                      Email
                      <input
                        name="email"
                        type="email"
                        required
                        maxLength={320}
                      />
                    </label>
                    <label className="field">
                      Temporary password
                      <input
                        name="password"
                        type="password"
                        required
                        minLength={12}
                        maxLength={1024}
                      />
                    </label>
                    <label className="field">
                      Role
                      <select
                        value={accountRole}
                        onChange={(e) => setAccountRole(e.target.value)}
                      >
                        {(role === "owner"
                          ? ["owner", "admin", "responder", "viewer"]
                          : ["responder", "viewer"]
                        ).map((r) => (
                          <option key={r}>{r}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <div className="modalactions">
                    <button className="btn primary">
                      Create login account
                    </button>
                  </div>
                </form>
                {loginAccounts.map((a) => (
                  <article className="accessrow" key={a.id}>
                    <div>
                      <strong>{a.display_name}</strong>
                      <small>
                        {a.email} · {a.role} ·{" "}
                        {a.active ? "Active" : "Disabled"}
                      </small>
                    </div>
                  </article>
                ))}
              </>
            )}
          </section>
        )}
        \n{" "}
        {page === "users" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Users & channels</h2>
                <p>
                  Manage responders and their email or webhook destinations.
                </p>
              </div>
              <button
                className="btn primary"
                disabled={!canManage}
                onClick={() => {
                  setSelectedGroups([]);
                  setGroupDraftName("");
                  setUserModal(true);
                }}
              >
                ＋ Add user
              </button>
            </div>
            {!canManage ? (
              <div className="empty">Owner or admin access is required.</div>
            ) : users.length ? (
              users.map((u) => (
                <article className="accessrow" key={u.handle}>
                  <div>
                    <strong>{u.handle}</strong>
                    <small>
                      Team: {u.team || "—"} · Groups:{" "}
                      {(u.groups || []).join(", ") || "—"} ·{" "}
                      {Object.entries(u.channels || {})
                        .map(
                          ([c, v]) =>
                            `${c}: ${v.destination}${v.active ? "" : " (paused)"}`,
                        )
                        .join(" · ")}
                    </small>
                  </div>
                </article>
              ))
            ) : (
              <div className="empty">No responders configured yet.</div>
            )}
          </section>
        )}
        {page === "policies" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Escalation policies</h2>
                <p>
                  Configure ordered notification steps stored in PostgreSQL.
                </p>
              </div>
              <button
                className="btn primary"
                disabled={!canManage}
                onClick={() => setPolicyModal(true)}
              >
                ＋ New policy
              </button>
            </div>
            {policies.length ? (
              policies.map((p) => (
                <article className="accessrow" key={p.id}>
                  <div>
                    <strong>{p.name}</strong>
                    <small>
                      {p.timezone} · {p.steps?.length || 0} step(s)
                    </small>
                  </div>
                </article>
              ))
            ) : (
              <div className="empty">
                No escalation policies configured yet.
              </div>
            )}
          </section>
        )}
        {page === "schedules" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>On-call schedules</h2>
                <p>
                  Create rotating responder schedules, then use the schedule
                  name as the target in an escalation step set to “schedule”.
                  The rotation anchor is entered in your browser’s local time
                  and stored as UTC; the IANA timezone controls schedule
                  display.
                </p>
              </div>
            </div>
            {!canManage ? (
              <div className="empty">Owner or admin access is required.</div>
            ) : (
              <>
                <form className="form schedule-form" onSubmit={saveSchedule}>
                  <label className="field">
                    Schedule name
                    <input
                      required
                      maxLength={120}
                      value={scheduleName}
                      onChange={(e) => setScheduleName(e.target.value)}
                      placeholder="Primary on-call"
                    />
                  </label>
                  <label className="field">
                    IANA timezone
                    <input
                      required
                      value={scheduleTimezone}
                      onChange={(e) => setScheduleTimezone(e.target.value)}
                      placeholder="America/New_York"
                    />
                  </label>
                  <label className="field">
                    Rotation interval (minutes)
                    <input
                      required
                      type="number"
                      min={15}
                      max={43200}
                      value={scheduleInterval}
                      onChange={(e) =>
                        setScheduleInterval(Number(e.target.value))
                      }
                    />
                  </label>
                  <label className="field">
                    First rotation starts
                    <input
                      required
                      type="datetime-local"
                      value={scheduleStartsAt}
                      onChange={(e) => setScheduleStartsAt(e.target.value)}
                    />
                  </label>
                  <label className="field schedule-members">
                    Responder handles in rotation
                    <textarea
                      required
                      rows={3}
                      value={scheduleMembers}
                      onChange={(e) => setScheduleMembers(e.target.value)}
                      placeholder="alex, sam, jordan"
                    />
                    <small>
                      Separate handles with commas or new lines. Each handle
                      needs an active email or webhook channel.
                    </small>
                  </label>
                  <div className="schedule-actions">
                    <button className="btn primary">
                      {editingScheduleId ? "Save schedule" : "Create schedule"}
                    </button>
                    {editingScheduleId && (
                      <button
                        type="button"
                        className="btn"
                        onClick={clearScheduleDraft}
                      >
                        Cancel edit
                      </button>
                    )}
                  </div>
                </form>
                {schedules.length ? (
                  schedules.map((s) => {
                    const elapsed =
                      Date.now() - new Date(s.rotation_starts_at).getTime();
                    const slot =
                      elapsed < 0
                        ? null
                        : Math.floor(
                            elapsed / (s.rotation_interval_minutes * 60000),
                          ) % s.members.length;
                    const nextAt =
                      elapsed < 0
                        ? new Date(s.rotation_starts_at)
                        : new Date(
                            new Date(s.rotation_starts_at).getTime() +
                              (Math.floor(
                                elapsed / (s.rotation_interval_minutes * 60000),
                              ) +
                                1) *
                                s.rotation_interval_minutes *
                                60000,
                          );
                    return (
                      <article className="accessrow" key={s.id}>
                        <div>
                          <strong>{s.name}</strong>
                          <small>
                            {s.timezone} · every {s.rotation_interval_minutes}{" "}
                            minutes ·{" "}
                            {slot === null
                              ? `Starts ${new Intl.DateTimeFormat([], { timeZone: s.timezone, dateStyle: "medium", timeStyle: "short" }).format(new Date(s.rotation_starts_at))}`
                              : `On call: ${s.members[slot]}`}{" "}
                            · Next rotation{" "}
                            {new Intl.DateTimeFormat([], {
                              timeZone: s.timezone,
                              dateStyle: "medium",
                              timeStyle: "short",
                            }).format(nextAt)}
                          </small>
                          <small>Rotation order: {s.members.join(" → ")}</small>
                        </div>
                        <div className="row-actions">
                          <button
                            className="btn"
                            onClick={() => editSchedule(s)}
                          >
                            Edit
                          </button>
                          <button
                            className="btn danger"
                            onClick={() => removeSchedule(s.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </article>
                    );
                  })
                ) : (
                  <div className="empty">
                    No schedules configured. Add responder channels first, then
                    create a schedule.
                  </div>
                )}
              </>
            )}
          </section>
        )}
        {page === "deliveries" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Notification deliveries</h2>
                <p>Queued messages, retries, and dead-letter notifications.</p>
              </div>
              <button
                className="btn"
                disabled={!canManage}
                onClick={openDeliveries}
              >
                ↻ Refresh
              </button>
            </div>
            {!canManage ? (
              <div className="empty">Owner or admin access is required.</div>
            ) : deliveries.length ? (
              deliveries.map((d) => (
                <article className="accessrow" key={d.id}>
                  <div>
                    <strong>
                      {d.channel} · {d.status}
                    </strong>
                    <small>
                      {d.attempts} attempt(s) ·{" "}
                      {d.last_error || d.next_attempt_at || d.id}
                    </small>
                  </div>
                  {d.status === "dead" && (
                    <button className="btn" onClick={() => retryDelivery(d.id)}>
                      Retry
                    </button>
                  )}
                </article>
              ))
            ) : (
              <div className="empty">No notification deliveries yet.</div>
            )}
          </section>
        )}
        {page === "integrations" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Integrations</h2>
                <p>
                  Configure tenant-specific connector settings. Credentials
                  belong in a secret manager.
                </p>
              </div>
              <div className="integration-page-actions">
                <button
                  className="btn"
                  disabled={!canManage}
                  onClick={openIntegrations}
                >
                  ↻ Refresh
                </button>
                <button
                  className="btn primary"
                  disabled={!canManage}
                  onClick={() => setConnectorPicker(true)}
                >
                  ＋ Add integration
                </button>
              </div>
            </div>
            {!canManage ? (
              <div className="empty">Owner or admin access is required.</div>
            ) : (
              <>
                <h3>Configured integrations</h3>
                {integrations.length ? (
                  <div className="integration-list">
                    {integrations.map((i) => {
                      const c = connectors.find(
                        (x) => x.key === i.connector_key,
                      );
                      return (
                        <article className="integration-row" key={i.id}>
                          <div className="integration-main">
                            <strong>{i.name}</strong>
                            <span className="integration-tag">
                              {c?.category || i.connector_key}
                            </span>
                            <small>
                              {c?.name || i.connector_key} ·{" "}
                              {i.enabled ? "Enabled" : "Disabled"} ·{" "}
                              {i.validation_status.replace("_", " ")}
                              {i.credential_reference
                                ? ` · Secret ref: ${i.credential_reference}`
                                : " · No credential reference"}
                            </small>
                            <small>
                              {Object.entries(i.configuration || {})
                                .filter(([k]) => k !== "payload_fields")
                                .map(([k, v]) => `${k}: ${String(v)}`)
                                .join(" · ") || "No connector fields set"}
                            </small>
                            <small>
                              {Array.isArray(i.configuration.payload_fields)
                                ? i.configuration.payload_fields.length
                                : 0}{" "}
                              custom payload field(s)
                            </small>
                          </div>
                          <div className="integration-actions">
                            <button
                              className="btn"
                              onClick={() => c && beginIntegration(c, i)}
                            >
                              Edit
                            </button>
                            <button
                              className="btn"
                              onClick={() => validateIntegration(i.id)}
                            >
                              Validate fields
                            </button>
                            <button
                              className="btn danger"
                              onClick={() => removeIntegration(i.id)}
                            >
                              Remove
                            </button>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  <div className="empty">
                    No integrations configured for this tenant.
                  </div>
                )}
                <div className="notice">
                  Use Add integration to choose a connector and configure its
                  settings and payload field schema. Payload field definitions
                  are stored with the integration; provider adapters must
                  support them to process those fields.
                </div>
              </>
            )}
          </section>
        )}
        {page === "tenants" && (
          <section className="panel settings-page">
            <div className="heading">
              <div>
                <h2>Tenants</h2>
                <p>
                  {productOwner
                    ? "Product owner tenant administration."
                    : "Your tenant workspace."}
                </p>
              </div>
            </div>
            {productOwner && (
              <form onSubmit={createTenant}>
                <div className="form">
                  <label className="field">
                    Tenant name
                    <input name="name" required maxLength={120} />
                  </label>
                  <label className="field">
                    Slug
                    <input
                      name="slug"
                      required
                      minLength={2}
                      maxLength={60}
                      pattern="[a-z0-9-]+"
                    />
                  </label>
                </div>
                <div className="modalactions">
                  <button className="btn primary">Create tenant</button>
                </div>
              </form>
            )}
            {tenantSecret && (
              <div className="warning">
                Copy this tenant key now. It is shown only once.
                <div className="key">{tenantSecret}</div>
                <button
                  className="btn"
                  onClick={() =>
                    navigator.clipboard
                      .writeText(tenantSecret)
                      .then(() => ping("Tenant key copied"))
                  }
                >
                  Copy key
                </button>
              </div>
            )}
            {tenants.map((t) => (
              <article
                className="accessrow tenant-row"
                key={t.id}
                onContextMenu={(e) => {
                  if (!productOwner) return;
                  e.preventDefault();
                  setTenantMenu({ tenant: t, x: e.clientX, y: e.clientY });
                }}
              >
                <div>
                  <strong>{t.name}</strong>
                  <small>
                    {t.slug} · {t.id}
                    {productOwner ? " · Right-click to manage API keys" : ""}
                  </small>
                </div>
              </article>
            ))}
          </section>
        )}
        {connectorPicker && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setConnectorPicker(false);
            }}
          >
            <section className="modal connector-picker">
              <div className="heading">
                <div>
                  <h3>Choose a connector</h3>
                  <p>
                    Select a connector to configure its settings and payload
                    fields.
                  </p>
                </div>
                <button
                  type="button"
                  className="btn"
                  onClick={() => setConnectorPicker(false)}
                >
                  Close
                </button>
              </div>
              <div className="catalog-grid">
                {connectors.map((c) => (
                  <article className="connector-card" key={c.key}>
                    <div className="connector-icon">
                      {c.category === "Notifications"
                        ? "↗"
                        : c.category === "ITSM"
                          ? "▤"
                          : c.category === "Chat"
                            ? "☏"
                            : "⌁"}
                    </div>
                    <div className="connector-info">
                      <strong>{c.name}</strong>
                      <small>{c.summary}</small>
                      <div
                        className={
                          c.supported
                            ? "connector-status"
                            : "connector-status pending"
                        }
                      >
                        {c.supported
                          ? "● Delivery adapter available"
                          : "◌ Configuration only · adapter not installed"}
                      </div>
                      <button
                        type="button"
                        className="btn primary"
                        onClick={() => chooseConnector(c)}
                      >
                        Choose connector
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          </div>
        )}{" "}
        {integrationModal && editingConnector && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setIntegrationModal(false);
            }}
          >
            <section className="modal">
              <h3>
                {editingIntegration ? "Edit" : "Configure"}{" "}
                {editingConnector.name}
              </h3>
              <p>{editingConnector.summary}</p>
              <form onSubmit={saveIntegration}>
                <div className="form">
                  <label className="field full">
                    Integration name
                    <input
                      name="name"
                      required
                      maxLength={120}
                      defaultValue={
                        editingIntegration?.name || editingConnector.name
                      }
                    />
                  </label>
                  {editingConnector.fields
                    .filter((x) => x !== "credential_reference")
                    .map((field) => (
                      <label className="field" key={field}>
                        {field.replaceAll("_", " ")}
                        <input
                          name={field}
                          defaultValue={String(
                            editingIntegration?.configuration?.[field] || "",
                          )}
                          placeholder={field.endsWith("url") ? "https://…" : ""}
                          type={field.endsWith("url") ? "url" : "text"}
                        />
                      </label>
                    ))}
                  <div className="payload-config field full">
                    <div className="payload-head">
                      <div>
                        <strong>Payload fields</strong>
                        <small>
                          Describe fields expected from this connector using dot
                          paths for nested JSON.
                        </small>
                      </div>
                      <button
                        type="button"
                        className="btn"
                        onClick={() =>
                          setPayloadFields([
                            ...payloadFields,
                            {
                              path: "",
                              type: "string",
                              required: false,
                              description: "",
                            },
                          ])
                        }
                      >
                        ＋ Add field
                      </button>
                    </div>
                    {payloadFields.map((field, index) => (
                      <div className="payload-row" key={index}>
                        <label className="field">
                          Payload path
                          <input
                            required
                            maxLength={200}
                            value={field.path}
                            placeholder="data.region"
                            onChange={(e) =>
                              setPayloadFields(
                                payloadFields.map((x, i) =>
                                  i === index
                                    ? { ...x, path: e.target.value }
                                    : x,
                                ),
                              )
                            }
                          />
                        </label>
                        <label className="field">
                          Type
                          <select
                            value={field.type}
                            onChange={(e) =>
                              setPayloadFields(
                                payloadFields.map((x, i) =>
                                  i === index
                                    ? {
                                        ...x,
                                        type: e.target
                                          .value as PayloadField["type"],
                                      }
                                    : x,
                                ),
                              )
                            }
                          >
                            {[
                              "string",
                              "number",
                              "boolean",
                              "object",
                              "array",
                            ].map((t) => (
                              <option key={t}>{t}</option>
                            ))}
                          </select>
                        </label>
                        <label className="field">
                          Description
                          <input
                            maxLength={300}
                            value={field.description}
                            placeholder="Region where alert originated"
                            onChange={(e) =>
                              setPayloadFields(
                                payloadFields.map((x, i) =>
                                  i === index
                                    ? { ...x, description: e.target.value }
                                    : x,
                                ),
                              )
                            }
                          />
                        </label>
                        <label className="field payload-required">
                          <input
                            type="checkbox"
                            checked={field.required}
                            onChange={(e) =>
                              setPayloadFields(
                                payloadFields.map((x, i) =>
                                  i === index
                                    ? { ...x, required: e.target.checked }
                                    : x,
                                ),
                              )
                            }
                          />{" "}
                          Required
                        </label>
                        <button
                          type="button"
                          className="btn danger"
                          onClick={() =>
                            setPayloadFields(
                              payloadFields.filter((_, i) => i !== index),
                            )
                          }
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                  <label className="field full">
                    Secret manager reference (optional)
                    <input
                      name="credential_reference"
                      defaultValue={
                        editingIntegration?.credential_reference || ""
                      }
                      placeholder="vault://team/integration"
                    />
                  </label>
                  <label className="field full checkbox-field">
                    <input
                      name="enabled"
                      type="checkbox"
                      defaultChecked={editingIntegration?.enabled ?? true}
                    />{" "}
                    Enable this integration
                  </label>
                </div>
                <div className="notice">
                  Store only a reference to a vault or secret manager here. Raw
                  tokens and passwords are rejected by the API. Payload fields
                  describe the expected payload schema; an adapter must support
                  them to process payloads.
                </div>
                <div className="modalactions">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setIntegrationModal(false)}
                  >
                    Cancel
                  </button>
                  <button className="btn primary">Save integration</button>
                </div>
              </form>
            </section>
          </div>
        )}{" "}
        {userModal && (
          <div className="veil">
            <section className="modal">
              <h3>Add responder</h3>
              <p>Configure at least one notification destination.</p>
              <form onSubmit={saveUser}>
                <div className="form">
                  <label className="field">
                    Handle
                    <input
                      name="handle"
                      required
                      maxLength={120}
                      placeholder="alex-oncall"
                    />
                  </label>
                  <label className="field">
                    Primary team / schedule group
                    <input
                      name="team"
                      maxLength={120}
                      placeholder="platform-oncall"
                    />
                  </label>
                  <label className="field full">
                    Team and group memberships
                    <div className="group-membership">
                      {groupChoices.length ? (
                        groupChoices.map((g) => (
                          <label className="group-check" key={g}>
                            <input
                              type="checkbox"
                              checked={selectedGroups.includes(g)}
                              onChange={(e) =>
                                setSelectedGroups(
                                  e.target.checked
                                    ? [...selectedGroups, g]
                                    : selectedGroups.filter((x) => x !== g),
                                )
                              }
                            />
                            {g}
                          </label>
                        ))
                      ) : (
                        <small>No existing groups yet. Add one below.</small>
                      )}
                      <div className="group-add">
                        <input
                          value={groupDraftName}
                          maxLength={120}
                          placeholder="Add a group, e.g. database-oncall"
                          onChange={(e) => setGroupDraftName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              const name = groupDraftName.trim();
                              if (name && !selectedGroups.includes(name))
                                setSelectedGroups([...selectedGroups, name]);
                              setGroupDraftName("");
                            }
                          }}
                        />
                        <button
                          type="button"
                          className="btn"
                          onClick={() => {
                            const name = groupDraftName.trim();
                            if (name && !selectedGroups.includes(name))
                              setSelectedGroups([...selectedGroups, name]);
                            setGroupDraftName("");
                          }}
                        >
                          Add group
                        </button>
                      </div>
                      {selectedGroups.map((g) => (
                        <span className="integration-tag" key={g}>
                          {g}
                        </span>
                      ))}
                    </div>
                  </label>
                  <label className="field full">
                    Email
                    <input
                      name="email"
                      type="email"
                      placeholder="oncall@example.com"
                    />
                  </label>
                  <label className="field full">
                    Webhook URL
                    <input
                      name="webhook"
                      type="url"
                      placeholder="https://hooks.example.com/alert"
                    />
                  </label>
                </div>
                <div className="modalactions">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setUserModal(false)}
                  >
                    Cancel
                  </button>
                  <button className="btn primary">Save user</button>
                </div>
              </form>
            </section>
          </div>
        )}
        {policyModal && (
          <div className="veil">
            <section className="modal policy-modal">
              <h3>New escalation policy</h3>
              <p>The first target step starts immediately.</p>
              <form onSubmit={savePolicy}>
                <div className="form">
                  <label className="field">
                    Name
                    <input name="name" required maxLength={120} />
                  </label>
                  <label className="field">
                    IANA time zone
                    <input
                      name="timezone"
                      required
                      defaultValue="Asia/Kolkata"
                    />
                  </label>
                  <label className="field full">
                    Description
                    <input name="description" maxLength={1000} />
                  </label>
                  <label className="field">
                    Repeat count
                    <input
                      name="repeat_count"
                      type="number"
                      min="0"
                      max="20"
                      defaultValue="0"
                    />
                  </label>
                  <label className="field">
                    Repeat interval (minutes)
                    <input
                      name="repeat_every_minutes"
                      type="number"
                      min="1"
                      max="10080"
                      defaultValue="30"
                    />
                  </label>
                </div>
                <h4>Escalation steps</h4>
                {draftSteps.map((step, i) => (
                  <div className="form stepform" key={i}>
                    <label className="field">
                      Wait minutes
                      <input
                        type="number"
                        min="0"
                        max="10080"
                        value={step.delay_minutes}
                        onChange={(e) =>
                          setDraftSteps(
                            draftSteps.map((s, j) =>
                              j === i
                                ? {
                                    ...s,
                                    delay_minutes: Number(e.target.value),
                                  }
                                : s,
                            ),
                          )
                        }
                      />
                    </label>
                    <label className="field">
                      Target type
                      <select
                        value={step.target_type}
                        onChange={(e) =>
                          setDraftSteps(
                            draftSteps.map((s, j) =>
                              j === i
                                ? {
                                    ...s,
                                    target_type: e.target.value,
                                    target: "",
                                  }
                                : s,
                            ),
                          )
                        }
                      >
                        {["user", "team", "schedule", "channel"].map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                    </label>
                    <label className="field">
                      Who should be notified?
                      <select
                        required
                        value={step.target}
                        onChange={(e) =>
                          setDraftSteps(
                            draftSteps.map((s, j) =>
                              j === i ? { ...s, target: e.target.value } : s,
                            ),
                          )
                        }
                      >
                        <option value="" disabled>
                          Select a recipient or group
                        </option>
                        {step.target_type === "user"
                          ? users.map((u) => (
                              <option key={u.handle} value={u.handle}>
                                {u.handle}
                              </option>
                            ))
                          : step.target_type === "team"
                            ? groupChoices.map((g) => (
                                <option key={g} value={g}>
                                  {g}
                                </option>
                              ))
                            : step.target_type === "schedule"
                              ? schedules.map((s) => (
                                  <option key={s.id} value={s.name}>
                                    {s.name} · {s.timezone}
                                  </option>
                                ))
                              : users.flatMap((u) =>
                                  Object.entries(u.channels || {})
                                    .filter(([, c]) => c.active)
                                    .map(([channel, c]) => (
                                      <option
                                        key={`${u.handle}-${channel}`}
                                        value={c.destination}
                                      >
                                        {u.handle} · {channel} ({c.destination})
                                      </option>
                                    )),
                                )}
                      </select>
                    </label>
                    <button
                      className="btn"
                      type="button"
                      disabled={draftSteps.length === 1}
                      onClick={() =>
                        setDraftSteps(draftSteps.filter((_, j) => j !== i))
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <button
                  className="btn"
                  type="button"
                  disabled={draftSteps.length >= 10}
                  onClick={() =>
                    setDraftSteps([
                      ...draftSteps,
                      { delay_minutes: 10, target_type: "user", target: "" },
                    ])
                  }
                >
                  ＋ Add step
                </button>
                <div className="modalactions">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setPolicyModal(false)}
                  >
                    Cancel
                  </button>
                  <button className="btn primary">Save policy</button>
                </div>
              </form>
            </section>
          </div>
        )}
        {modal && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setModal(null);
            }}
          >
            <section className="modal">
              <h3>
                {modal === "test"
                  ? "Run an end-to-end test"
                  : "Create an incident"}
              </h3>
              <p>
                {modal === "test"
                  ? "Create a labeled incident through a real escalation policy."
                  : "Submit a manual alert into the incident workflow."}
              </p>
              <form onSubmit={(e) => submitIncident(e, modal === "test")}>
                <div className="form">
                  <label className="field full">
                    Title
                    <input
                      name="title"
                      required
                      maxLength={200}
                      defaultValue={
                        modal === "test" ? "RelayOps test incident" : ""
                      }
                      placeholder="Describe the incident"
                    />
                  </label>
                  {modal === "incident" && (
                    <label className="field">
                      Deduplication key
                      <input
                        name="dedup_key"
                        required
                        placeholder="service/condition"
                      />
                    </label>
                  )}
                  <label className="field">
                    Service
                    <input name="service" required placeholder="payments-api" />
                  </label>
                  {modal === "incident" && (
                    <label className="field">
                      Source
                      <input name="source" defaultValue="manual" />
                      <small className="field-help">
                        Source identifies the system or workflow that raised
                        this alert (for example, Prometheus, a deployment
                        monitor, or manual). It is a label for filtering and
                        reporting; it does not select a notification channel.
                      </small>
                    </label>
                  )}
                  <label className="field">
                    Severity
                    <select name="severity" defaultValue="warning">
                      {["critical", "error", "warning", "info"].map((x) => (
                        <option key={x}>{x}</option>
                      ))}
                    </select>
                  </label>
                  <label className="field full">
                    Escalation policy
                    <select
                      name="policy"
                      required={modal === "test"}
                      defaultValue=""
                    >
                      <option value="">
                        {modal === "test" ? "Choose a policy" : "No policy"}
                      </option>
                      {policies.map((p) => (
                        <option value={p.id} key={p.id}>
                          {p.name} · {p.timezone}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field full">
                    Description
                    <textarea
                      name="description"
                      defaultValue={
                        modal === "test"
                          ? "Test created from the RelayOps Next.js dashboard."
                          : ""
                      }
                      maxLength={1000}
                    />
                  </label>
                </div>
                {modal === "test" && (
                  <div className="warning">
                    This sends a real incident through the escalation worker and
                    can notify every active email/webhook target in the selected
                    policy. Use test destinations first.
                  </div>
                )}
                <div className="modalactions">
                  <button
                    className="btn"
                    type="button"
                    onClick={() => setModal(null)}
                  >
                    Cancel
                  </button>
                  <button className="btn primary" disabled={busy}>
                    {busy
                      ? "Creating…"
                      : modal === "test"
                        ? "Create test incident"
                        : "Create incident"}
                  </button>
                </div>
              </form>
            </section>
          </div>
        )}
        {settings && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setSettings(false);
            }}
          >
            <section className="modal">
              <h3>Connect to the Rust API</h3>
              <p>
                Enter the tenant API key. Access and role checks are performed
                by the backend.
              </p>
              <label className="field">
                Tenant API key
                <input
                  type="password"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="Paste a tenant API key"
                />
              </label>
              <label className="field" style={{ marginTop: 14 }}>
                Navigation location
                <select
                  value={navPosition}
                  onChange={(e) => {
                    const p = e.target.value as
                      | "left"
                      | "right"
                      | "top"
                      | "bottom";
                    setNavPosition(p);
                    localStorage.setItem("relayops.navPosition", p);
                  }}
                >
                  <option value="left">Left</option>
                  <option value="right">Right</option>
                  <option value="top">Top</option>
                  <option value="bottom">Bottom</option>
                </select>
              </label>
              <div className="warning">
                The key is stored in this browser's local storage. Use an
                individual key and avoid shared computers. The Next.js service
                forwards API requests to Rust.
              </div>
              <div className="modalactions">
                <button className="btn" onClick={() => setSettings(false)}>
                  Cancel
                </button>
                <button className="btn primary" onClick={saveSettings}>
                  Connect
                </button>
              </div>
            </section>
          </div>
        )}
        {access && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setAccess(false);
            }}
          >
            <section className="modal">
              <h3>Access & roles</h3>
              <p>
                Your access role: <strong>{role || "unknown"}</strong>. Role
                checks are enforced by Rust middleware.
              </p>
              {canManage ? (
                <>
                  <form onSubmit={createKey}>
                    <div className="form">
                      <label className="field">
                        Key name
                        <input
                          required
                          maxLength={120}
                          value={newKeyName}
                          onChange={(e) => setNewKeyName(e.target.value)}
                          placeholder="Monitoring integration"
                        />
                      </label>
                      <label className="field">
                        Role
                        <select
                          value={newKeyRole}
                          onChange={(e) => setNewKeyRole(e.target.value)}
                        >
                          {(role === "owner" ? roles : roles.slice(2)).map(
                            (r) => (
                              <option key={r}>{r}</option>
                            ),
                          )}
                        </select>
                      </label>
                      <label className="field">
                        Expires (optional)
                        <input
                          type="datetime-local"
                          value={newKeyExpiry}
                          onChange={(e) => setNewKeyExpiry(e.target.value)}
                        />
                      </label>
                    </div>
                    <div className="modalactions">
                      <button className="btn primary">Create API key</button>
                    </div>
                  </form>
                  {secret && (
                    <div className="warning">
                      Copy this key now. It is shown only once.
                      <div className="key">{secret}</div>
                      <button
                        className="btn"
                        style={{ marginTop: 8 }}
                        onClick={() =>
                          navigator.clipboard
                            .writeText(secret)
                            .then(() => ping("Key copied"))
                        }
                      >
                        Copy key
                      </button>
                    </div>
                  )}
                  {keys.map((k) => (
                    <div className="accessrow" key={k.id}>
                      <div>
                        <strong>{k.name}</strong>
                        <small>
                          {k.role} ·{" "}
                          {k.active
                            ? "Active"
                            : k.expires_at &&
                                new Date(k.expires_at) <= new Date()
                              ? "Expired"
                              : "Revoked"}
                          {k.last_used_at
                            ? ` · Used ${pretty(k.last_used_at)}`
                            : ""}
                          {k.expires_at
                            ? ` · Expires ${pretty(k.expires_at)}`
                            : " · No expiry"}
                        </small>
                        <label className="field" style={{ marginTop: 8 }}>
                          Expiration (your local time)
                          <input
                            type="datetime-local"
                            value={
                              keyExpiryDrafts[k.id] ??
                              (k.expires_at ? localDateTime(k.expires_at) : "")
                            }
                            onChange={(e) =>
                              setKeyExpiryDrafts({
                                ...keyExpiryDrafts,
                                [k.id]: e.target.value,
                              })
                            }
                          />
                        </label>
                        <button
                          className="btn"
                          style={{ marginTop: 7 }}
                          onClick={() => saveKeyExpiry(k.id)}
                        >
                          Save expiration
                        </button>
                      </div>
                      <div className="row-actions">
                        <button
                          className="btn"
                          disabled={!k.active}
                          onClick={() => rotateKey(k.id)}
                        >
                          Change key
                        </button>
                        <button className="btn" onClick={() => revoke(k.id)}>
                          Revoke
                        </button>
                      </div>
                    </div>
                  ))}
                </>
              ) : (
                <div className="notice">
                  Key management requires an owner or admin role. Incident
                  access available to this key is controlled by its role.
                </div>
              )}
              <div className="modalactions">
                <button className="btn" onClick={() => setAccess(false)}>
                  Done
                </button>
              </div>
            </section>
          </div>
        )}
        {tenantMenu && (
          <div className="context-backdrop" onClick={() => setTenantMenu(null)}>
            <div
              className="context-menu"
              style={{
                left: Math.min(tenantMenu.x, window.innerWidth - 230),
                top: Math.min(tenantMenu.y, window.innerHeight - 110),
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <strong>{tenantMenu.tenant.name}</strong>
              <button onClick={() => loadManagedTenantKeys(tenantMenu.tenant)}>
                Manage API keys
              </button>
              <button
                onClick={() =>
                  navigator.clipboard
                    .writeText(tenantMenu.tenant.id)
                    .then(() => {
                      ping("Tenant ID copied");
                      setTenantMenu(null);
                    })
                }
              >
                Copy tenant ID
              </button>
            </div>
          </div>
        )}
        {incidentMenu && (
          <div
            className="context-backdrop"
            onClick={() => setIncidentMenu(null)}
          >
            <div
              className="context-menu"
              style={{
                left: Math.min(incidentMenu.x, window.innerWidth - 220),
                top: Math.min(incidentMenu.y, window.innerHeight - 190),
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <strong>{incidentMenu.incident.incident_number}</strong>
              <button
                onClick={() => {
                  choose(incidentMenu.incident);
                  setIncidentMenu(null);
                }}
              >
                View details
              </button>
              {canRespond &&
                incidentMenu.incident.status !== "acknowledged" &&
                incidentMenu.incident.status !== "resolved" && (
                  <button
                    onClick={() =>
                      actOnIncident(incidentMenu.incident, "acknowledge")
                    }
                  >
                    Acknowledge
                  </button>
                )}
              {canRespond && incidentMenu.incident.status !== "resolved" && (
                <button
                  onClick={() =>
                    actOnIncident(incidentMenu.incident, "resolve")
                  }
                >
                  Resolve
                </button>
              )}
              <button
                onClick={() =>
                  navigator.clipboard
                    .writeText(incidentMenu.incident.incident_number)
                    .then(() => {
                      ping("Incident ID copied");
                      setIncidentMenu(null);
                    })
                }
              >
                Copy incident ID
              </button>
            </div>
          </div>
        )}
        {managedTenant && (
          <div
            className="veil"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setManagedTenant(null);
            }}
          >
            <section className="modal tenant-keys-modal">
              <div className="heading">
                <div>
                  <h3>{managedTenant.name} API keys</h3>
                  <p>Rotate, revoke, or update expiration for this tenant.</p>
                </div>
                <button className="btn" onClick={() => setManagedTenant(null)}>
                  Close
                </button>
              </div>
              {managedTenantSecret && (
                <div className="warning">
                  Copy this replacement secret now. It is shown only once.
                  <div className="key">{managedTenantSecret}</div>
                  <button
                    className="btn"
                    style={{ marginTop: 8 }}
                    onClick={() =>
                      navigator.clipboard
                        .writeText(managedTenantSecret)
                        .then(() => ping("Replacement key copied"))
                    }
                  >
                    Copy key
                  </button>
                </div>
              )}
              {managedTenantKeys.length ? (
                managedTenantKeys.map((k) => (
                  <article className="accessrow tenant-key-row" key={k.id}>
                    <div>
                      <strong>{k.name}</strong>
                      <small>
                        {k.role} ·{" "}
                        {k.active
                          ? "Active"
                          : k.expires_at && new Date(k.expires_at) <= new Date()
                            ? "Expired"
                            : "Revoked"}
                        {k.last_used_at
                          ? ` · Used ${pretty(k.last_used_at)}`
                          : ""}
                        {k.expires_at
                          ? ` · Expires ${pretty(k.expires_at)}`
                          : " · No expiry"}
                      </small>
                      <label className="field" style={{ marginTop: 8 }}>
                        Expiration (your local time)
                        <input
                          type="datetime-local"
                          value={
                            managedExpiryDrafts[k.id] ??
                            (k.expires_at ? localDateTime(k.expires_at) : "")
                          }
                          onChange={(e) =>
                            setManagedExpiryDrafts({
                              ...managedExpiryDrafts,
                              [k.id]: e.target.value,
                            })
                          }
                        />
                      </label>
                      <button
                        className="btn"
                        style={{ marginTop: 7 }}
                        onClick={() => saveManagedExpiration(k.id)}
                      >
                        Save expiration
                      </button>
                    </div>
                    <div className="row-actions">
                      <button
                        className="btn"
                        disabled={!k.active}
                        onClick={() => rotateManagedKey(k.id)}
                      >
                        Change key
                      </button>
                      <button
                        className="btn danger"
                        onClick={() => revokeManagedKey(k.id)}
                      >
                        Revoke
                      </button>
                    </div>
                  </article>
                ))
              ) : (
                <div className="empty">
                  No API keys are configured for this tenant.
                </div>
              )}
            </section>
          </div>
        )}
        {toast && <div className="toast">{toast}</div>}
      </main>
    </div>
  );
}
