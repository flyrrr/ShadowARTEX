package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/opsec"
)

func opsecApplyPacing(enabled bool) {
	if !enabled {
		return
	}
	if egress.CurrentProfile().RPS > 0 {
		return
	}
	if p, ok := egress.ProfileByName("quiet"); ok {
		egress.SetProfile(p)
	}
}

func (m *Manager) opsecBypassFromLLM() []string {
	profiles, err := m.pg.ListProfiles()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range profiles {
		if p == nil || strings.TrimSpace(p.BaseURL) == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(p.BaseURL))
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func (m *Manager) buildOpsecConfig() opsec.Config {
	cfg := opsec.Config{Enabled: m.pg.GetBool(pgdb.SettingOpsecEnabled, false)}
	if v, ok, _ := m.pg.GetSetting(pgdb.SettingOpsecTorHost); ok {
		cfg.TorHost = strings.TrimSpace(v)
	}

	if cfg.TorHost == "" {
		cfg.TorHost = strings.TrimSpace(os.Getenv("ARTEX_OPSEC_TOR_HOST"))
	}
	if v, ok, _ := m.pg.GetSetting(pgdb.SettingOpsecTorPort); ok {
		cfg.TorPort, _ = strconv.Atoi(strings.TrimSpace(v))
	}
	if v, ok, _ := m.pg.GetSetting(pgdb.SettingOpsecControlPort); ok {
		cfg.ControlPort, _ = strconv.Atoi(strings.TrimSpace(v))
	}
	cfg.Bypass = append(parseBypassList(m.opsecBypassSetting()), m.opsecBypassFromLLM()...)
	return cfg
}

func (m *Manager) opsecBypassSetting() string {
	v, _, _ := m.pg.GetSetting(pgdb.SettingOpsecBypassList)
	return v
}

func parseBypassList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (m *Manager) loadOpsec() {
	opsec.SetLeakSink(func(l opsec.Leak) {
		if err := m.pg.InsertOpsecLeak(pgdb.OpsecLeak{
			TS: l.TS, Worker: l.Worker, Tool: l.Tool, Target: l.Target, Reason: l.Reason,
		}); err != nil {
			log.Printf("[opsec] persist leak: %v", err)
		}
	})
	st := opsec.SetConfig(m.buildOpsecConfig())
	opsecApplyPacing(st.Enabled())
	if st.Enabled() {
		for _, r := range st.WriteConfigs() {
			if r.Err != "" {
				log.Printf("[opsec] write %s: %s (manual config may be needed)", r.Path, r.Err)
			}
		}
		log.Printf("[opsec] ON — external egress via Tor %s (docker=%v)", st.TorAddr(), st.InDocker())
	}
}

func (m *Manager) applyOpsec() error {
	st := opsec.SetConfig(m.buildOpsecConfig())
	opsecApplyPacing(st.Enabled())
	if st.Enabled() {
		for _, r := range st.WriteConfigs() {
			if r.Err != "" {
				log.Printf("[opsec] write %s: %s", r.Path, r.Err)
			}
		}
	}
	if m.traffic != nil {
		if err := m.traffic.SetUpstreamProxy(m.effectiveUpstream()); err != nil {
			return err
		}
	}
	m.syncBrowserMCPProxy()
	return nil
}

func (m *Manager) OpsecState() *opsec.State { return opsec.Current() }

type opsecSettingsInput struct {
	Enabled         *bool   `json:"enabled"`
	TorHost         *string `json:"tor_host"`
	TorPort         *int    `json:"tor_port"`
	ControlPort     *int    `json:"control_port"`
	ControlPassword *string `json:"control_password"`
	BypassList      *string `json:"bypass_list"`
}

func (m *Manager) SetOpsecConfig(in opsecSettingsInput) error {
	if in.Enabled != nil {
		if err := m.pg.SetBool(pgdb.SettingOpsecEnabled, *in.Enabled); err != nil {
			return err
		}
	}
	if in.TorHost != nil {
		if err := m.pg.SetSetting(pgdb.SettingOpsecTorHost, strings.TrimSpace(*in.TorHost)); err != nil {
			return err
		}
	}
	if in.TorPort != nil {
		if err := m.pg.SetSetting(pgdb.SettingOpsecTorPort, strconv.Itoa(*in.TorPort)); err != nil {
			return err
		}
	}
	if in.ControlPort != nil {
		if err := m.pg.SetSetting(pgdb.SettingOpsecControlPort, strconv.Itoa(*in.ControlPort)); err != nil {
			return err
		}
	}
	if in.ControlPassword != nil && !isMaskedSecret(*in.ControlPassword) {
		if err := m.pg.SetSetting(pgdb.SettingOpsecControlPass, *in.ControlPassword); err != nil {
			return err
		}
	}
	if in.BypassList != nil {
		if err := m.pg.SetSetting(pgdb.SettingOpsecBypassList, *in.BypassList); err != nil {
			return err
		}
	}
	return m.applyOpsec()
}

func (s *Server) opsecSettingsView() map[string]any {
	st := s.m.OpsecState()
	pass, _, _ := s.m.pg.GetSetting(pgdb.SettingOpsecControlPass)
	return map[string]any{
		"enabled":              st.Enabled(),
		"tor_host":             st.TorHost(),
		"tor_port":             st.TorPort(),
		"control_port":         st.ControlPort(),
		"control_password":     maskedSecret(pass),
		"control_password_set": pass != "",
		"bypass_list":          s.m.opsecBypassSetting(),
		"in_docker":            st.InDocker(),
		"tor_proxy_url":        st.TorProxyURL(),
		"derived_bypass":       s.m.opsecBypassFromLLM(),
		"tooling":              opsec.CheckTooling(),
		"proxychains_conf":     opsec.ProxychainsConfPath,
		"torsocks_conf":        opsec.TorsocksConfPath,
	}
}

func (s *Server) getOpsecSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.opsecSettingsView())
}

func (s *Server) putOpsecSettings(w http.ResponseWriter, r *http.Request) {
	var in opsecSettingsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, 400, err.Error())
		return
	}
	if in.TorPort != nil && (*in.TorPort < 1 || *in.TorPort > 65535) {
		writeErr(w, 400, "tor_port must be between 1 and 65535")
		return
	}
	if in.ControlPort != nil && (*in.ControlPort < 1 || *in.ControlPort > 65535) {
		writeErr(w, 400, "control_port must be between 1 and 65535")
		return
	}
	if err := s.m.SetOpsecConfig(in); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	s.rebuildAgents()
	writeJSON(w, 200, s.opsecSettingsView())
}

func (s *Server) rebuildAgents() {
	s.cfgMu.Lock()
	cfg, on := s.llmCfg, s.llmOn
	s.cfgMu.Unlock()
	if on {
		if err := s.applyLLM(cfg); err != nil {
			log.Printf("[opsec] rebuild agents: %v", err)
		}
	}
}

func (s *Server) opsecStatus(w http.ResponseWriter, r *http.Request) {
	st := s.m.OpsecState()
	writeJSON(w, 200, map[string]any{
		"enabled":    st.Enabled(),
		"tor_addr":   st.TorAddr(),
		"in_docker":  st.InDocker(),
		"tooling":    opsec.CheckTooling(),
		"bypass_cnt": len(s.m.opsecBypassFromLLM()),
	})
}

func (s *Server) opsecTestTor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st := s.m.OpsecState().TestTor(ctx)
	if !st.IsTor {
		opsec.LogLeak(opsec.Leak{Tool: "test", Target: st.Addr, Reason: "Test Tor: " + st.Err})
	}
	writeJSON(w, 200, st)
}

func (s *Server) opsecTestDNSLeak(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, 200, s.m.OpsecState().TestDNSLeak(ctx))
}

func (s *Server) opsecTestClearnetBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	res := s.m.OpsecState().TestClearnetBlock(req.Target)
	if res.Blocked {
		opsec.LogLeak(opsec.Leak{Tool: "test", Target: res.Target, Reason: "Test Clearnet Block: " + res.Reason})
	}
	writeJSON(w, 200, res)
}

func (s *Server) opsecNewnym(w http.ResponseWriter, r *http.Request) {
	pass, _, _ := s.m.pg.GetSetting(pgdb.SettingOpsecControlPass)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.m.OpsecState().NewNym(ctx, pass); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) opsecLeaks(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	leaks, err := s.m.pg.ListOpsecLeaks(limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"leaks": leaks})
}
