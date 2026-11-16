"use client";

import * as React from "react";

import {
  CircleCheckIcon,
  CircleXIcon,
  GlobeIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  TriangleAlertIcon,
  VenetianMaskIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { OpsecLeak, OpsecSettings, OpsecTorStatus } from "@/lib/types";

const MASK = "••••••••";

export default function OpsecPage() {
  const [loaded, setLoaded] = React.useState(false);
  const [settings, setSettings] = React.useState<OpsecSettings | null>(null);
  const [enabled, setEnabled] = React.useState(false);
  const [torHost, setTorHost] = React.useState("");
  const [torPort, setTorPort] = React.useState("9050");
  const [controlPort, setControlPort] = React.useState("9051");
  const [controlPassword, setControlPassword] = React.useState("");
  const [bypassList, setBypassList] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const [tor, setTor] = React.useState<OpsecTorStatus | null>(null);
  const [testing, setTesting] = React.useState(false);
  const [dnsResult, setDnsResult] = React.useState<string>("");
  const [clearnetResult, setClearnetResult] = React.useState<string>("");
  const [rotating, setRotating] = React.useState(false);
  const [leaks, setLeaks] = React.useState<OpsecLeak[]>([]);

  const apply = React.useCallback((s: OpsecSettings) => {
    setSettings(s);
    setEnabled(s.enabled);
    setTorHost(s.tor_host);
    setTorPort(String(s.tor_port));
    setControlPort(String(s.control_port));
    setControlPassword(s.control_password_set ? MASK : "");
    setBypassList(s.bypass_list ?? "");
  }, []);

  const reloadLeaks = React.useCallback(async () => {
    try {
      const r = await api.opsecLeaks(200);
      setLeaks(r.leaks ?? []);
    } catch (e) {
      void e;
    }
  }, []);

  React.useEffect(() => {
    (async () => {
      try {
        apply(await api.opsecSettings());
        await reloadLeaks();
      } catch (e) {
        toast.error(`Failed to load Opsec settings: ${String(e)}`);
      } finally {
        setLoaded(true);
      }
    })();
  }, [apply, reloadLeaks]);

  const save = async (override?: Partial<{ enabled: boolean }>) => {
    setSaving(true);
    try {
      const body = {
        enabled: override?.enabled ?? enabled,
        tor_host: torHost.trim(),
        tor_port: Number(torPort) || 9050,
        control_port: Number(controlPort) || 9051,
        bypass_list: bypassList,
        ...(controlPassword && controlPassword !== MASK ? { control_password: controlPassword } : {}),
      };
      const s = await api.putOpsecSettings(body);
      apply(s);
      toast.success("Opsec settings saved");
    } catch (e) {
      toast.error(`Save failed: ${String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (v: boolean) => {
    setEnabled(v);
    await save({ enabled: v });
    if (v) void runTestTor();
  };

  const runTestTor = async () => {
    setTesting(true);
    try {
      const st = await api.opsecTestTor();
      setTor(st);
      if (st.is_tor) toast.success(`Tor OK — exit ${st.exit_ip}`);
      else toast.error(st.error || "Tor check failed");
    } catch (e) {
      toast.error(`Test Tor failed: ${String(e)}`);
    } finally {
      setTesting(false);
      void reloadLeaks();
    }
  };

  const runTestDNS = async () => {
    try {
      const r = await api.opsecTestDNSLeak();
      setDnsResult(r.detail);
      r.ok ? toast.success("No DNS leak") : toast.error("DNS leak check failed");
    } catch (e) {
      toast.error(`Test DNS failed: ${String(e)}`);
    }
  };

  const runTestClearnet = async () => {
    try {
      const r = await api.opsecTestClearnetBlock();
      setClearnetResult(r.reason);
      r.blocked ? toast.success("Clearnet is blocked") : toast.message(r.reason);
      void reloadLeaks();
    } catch (e) {
      toast.error(`Test failed: ${String(e)}`);
    }
  };

  const rotate = async () => {
    setRotating(true);
    try {
      const r = await api.opsecNewnym();
      if (r.ok) {
        toast.success("New Tor circuit requested");
        void runTestTor();
      } else {
        toast.error(r.error || "NEWNYM failed");
      }
    } finally {
      setRotating(false);
    }
  };

  if (!loaded) return <div className="text-muted-foreground p-4 text-sm">Loading…</div>;

  const torDown = enabled && tor !== null && !tor.is_tor;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-center gap-2">
        <VenetianMaskIcon className="size-5" />
        <h1 className="text-xl font-semibold">Opsec</h1>
        <Badge variant={enabled ? "default" : "secondary"}>{enabled ? "ON" : "OFF"}</Badge>
      </div>
      <p className="text-muted-foreground -mt-2 text-sm">
        Enforces anonymous egress in code: with Opsec on, every external tool call (Bash, WebFetch,
        http, scanners) must exit through Tor. If Tor is down, external calls are blocked. Loopback, LAN, the local LLM, Postgres, the UI and the recording proxy
        stay direct.
      </p>

      {torDown && (
        <Alert variant="destructive">
          <TriangleAlertIcon className="size-4" />
          <AlertTitle>All external tool calls blocked</AlertTitle>
          <AlertDescription>
            Opsec is ON but Tor is unreachable at {tor?.addr}. Every external connection is failing
            closed. {tor?.error}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Enforcement</CardTitle>
          <CardDescription>
            {settings?.in_docker ? "Running in Docker" : "Running natively"} - default Tor host{" "}
            <code>{settings?.in_docker ? "host.docker.internal" : "127.0.0.1"}</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <Label>Opsec Enabled</Label>
              <p className="text-muted-foreground text-sm">Force all external egress through Tor.</p>
            </div>
            <Switch checked={enabled} disabled={saving} onCheckedChange={toggleEnabled} />
          </div>
          <Separator />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="tor-host">Tor host</Label>
              <Input
                id="tor-host"
                value={torHost}
                placeholder={settings?.in_docker ? "host.docker.internal" : "127.0.0.1"}
                onChange={(e) => setTorHost(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="tor-port">SOCKS5 port</Label>
              <Input id="tor-port" value={torPort} onChange={(e) => setTorPort(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ctrl-port">Control port (NEWNYM)</Label>
              <Input id="ctrl-port" value={controlPort} onChange={(e) => setControlPort(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ctrl-pass">Control password</Label>
              <Input
                id="ctrl-pass"
                type="password"
                value={controlPassword}
                placeholder="(none)"
                onChange={(e) => setControlPassword(e.target.value)}
              />
            </div>
          </div>
          <div className="text-muted-foreground text-xs">
            Effective proxy: <code>{settings?.tor_proxy_url}</code> · proxychains4{" "}
            {settings?.tooling.proxychains ? "installed" : "MISSING"} · torsocks{" "}
            {settings?.tooling.torsocks ? "installed" : "MISSING"} · tor{" "}
            {settings?.tooling.tor ? "installed" : "MISSING"}
          </div>
          <Button onClick={() => save()} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Status & tests</CardTitle>
          <CardDescription>Live Tor reachability, exit IP, and enforcement checks.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            {tor ? (
              tor.is_tor ? (
                <Badge variant="default" className="gap-1">
                  <CircleCheckIcon className="size-3.5" /> Tor exit {tor.exit_ip}
                </Badge>
              ) : (
                <Badge variant="destructive" className="gap-1">
                  <CircleXIcon className="size-3.5" /> {tor.reachable ? "Not a Tor exit" : "Unreachable"}
                </Badge>
              )
            ) : (
              <Badge variant="secondary">Not tested yet</Badge>
            )}
            {tor?.checked_at && (
              <span className="text-muted-foreground text-xs">
                last tested {new Date(tor.checked_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={runTestTor} disabled={testing}>
              <ShieldCheckIcon className="size-4" /> {testing ? "Testing…" : "Test Tor"}
            </Button>
            <Button variant="outline" onClick={runTestDNS}>
              <GlobeIcon className="size-4" /> Test DNS Leak
            </Button>
            <Button variant="outline" onClick={runTestClearnet}>
              <CircleXIcon className="size-4" /> Test Clearnet Block
            </Button>
            <Button variant="outline" onClick={rotate} disabled={rotating}>
              <RefreshCwIcon className="size-4" /> {rotating ? "Rotating…" : "New Circuit (NEWNYM)"}
            </Button>
          </div>
          {dnsResult && <p className="text-muted-foreground text-sm">DNS: {dnsResult}</p>}
          {clearnetResult && <p className="text-muted-foreground text-sm">Clearnet: {clearnetResult}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Bypass allowlist</CardTitle>
          <CardDescription>
            Hosts / IPs / CIDRs reached directly, never through Tor. Loopback, RFC1918 LAN,
            link-local, the UI, recording proxy, Postgres and Tor itself are always included.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={bypassList}
            placeholder="one per line, e.g.&#10;ollama.lan&#10;192.168.50.0/24&#10;.corp.internal"
            rows={4}
            onChange={(e) => setBypassList(e.target.value)}
          />
          {settings?.derived_bypass && settings.derived_bypass.length > 0 && (
            <p className="text-muted-foreground text-xs">
              Auto-derived from LLM profiles: {settings.derived_bypass.join(", ")}
            </p>
          )}
          <Button onClick={() => save()} disabled={saving} variant="secondary">
            Save allowlist
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Blocked / leak log</CardTitle>
            <CardDescription>Blocked clearnet attempts, un-proxyable scans, and Tor failures.</CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={reloadLeaks}>
            <RefreshCwIcon className="size-4" /> Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {leaks.length === 0 ? (
            <p className="text-muted-foreground text-sm">No events recorded.</p>
          ) : (
            <div className="max-h-96 overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-40">Time</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {leaks.map((l) => (
                    <TableRow key={l.id}>
                      <TableCell className="text-xs">{new Date(l.ts).toLocaleString()}</TableCell>
                      <TableCell className="font-mono text-xs">{l.tool}</TableCell>
                      <TableCell className="max-w-xs truncate font-mono text-xs" title={l.target}>
                        {l.target}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{l.reason}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
