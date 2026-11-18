package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/vpn"
)

// vpnProfileView 是回给浏览器的出口配置：**不回传密码**，只给一个"已设置"的标志，
// 与其他密钥类设置的处理方式一致。
type vpnProfileView struct {
	db.VPNProfile
	Password    string     `json:"password,omitempty"` // 永远是空串，仅保留字段以对齐前端类型
	PasswordSet bool       `json:"password_set"`
	Status      vpn.Status `json:"status"`
}

// listVPNProfiles returns every profile with its live tunnel state.
func (s *Server) listVPNProfiles(w http.ResponseWriter, r *http.Request) {
	profs, err := s.m.pg.ListVPNProfiles()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]vpnProfileView, 0, len(profs))
	for _, p := range profs {
		st := vpn.Status{ID: p.ID, Name: p.Name, State: vpn.StateStopped}
		if s.m.vpnMgr != nil {
			// 配置上填了默认账号时才可能在"没跑任务"的情况下就有隧道。
			if p.Username != "" {
				st = s.m.vpnMgr.Status(vpnTunnelKey(p.ID, p.Username))
			}
		}
		v := vpnProfileView{VPNProfile: p, PasswordSet: strings.TrimSpace(p.Password) != "", Status: st}
		v.VPNProfile.Password = ""
		out = append(out, v)
	}
	// tunnels 是真正在跑的隧道，按账号列：界面要能直接看到"哪个项目、从哪个 IP 出去"。
	var tunnels []vpn.Status
	if s.m.vpnMgr != nil {
		tunnels = s.m.vpnMgr.Statuses()
	}
	writeJSON(w, 200, map[string]any{
		"profiles": out,
		"tunnels":  tunnels,
		// 让前端能明确区分"这台机器不支持 VPN 出口"，而不是显示一个永远连不上的开关。
		"supported": vpn.Supported(),
	})
}

// saveVPNProfile creates or updates a profile.
func (s *Server) saveVPNProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		OVPN         string `json:"ovpn"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		ExpectEgress string `json:"expect_egress"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "出口名称不能为空")
		return
	}
	prof := db.VPNProfile{
		ID: req.ID, Name: req.Name, OVPN: req.OVPN,
		Username: strings.TrimSpace(req.Username), Password: req.Password,
		ExpectEgress: strings.TrimSpace(req.ExpectEgress), Enabled: true,
	}
	if req.Enabled != nil {
		prof.Enabled = *req.Enabled
	}
	if prof.ID != 0 {
		// 更新时没带 .ovpn/账号就把原来的补回去：前端编辑页不一定回传全部字段。
		if old, err := s.m.pg.VPNProfileByID(prof.ID); err == nil && old != nil {
			if strings.TrimSpace(prof.OVPN) == "" {
				prof.OVPN = old.OVPN
			}
			if prof.Username == "" {
				prof.Username = old.Username
			}
		}
	}
	if strings.TrimSpace(prof.OVPN) == "" {
		writeErr(w, 400, "请上传 .ovpn 配置内容")
		return
	}
	// 只做校验不改写：原文入库，归一化在每次建链时按当前规则重新生成。
	if _, ok := vpn.RemoteAddr(prof.OVPN); !ok {
		writeErr(w, 400, "配置里找不到 remote 行，不是有效的 .ovpn")
		return
	}
	if err := s.m.pg.SaveVPNProfile(&prof); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 配置变了，旧隧道必须重建，否则用的还是上一份文件。
	if s.m.vpnMgr != nil {
		// 配置改了，基于它的所有隧道（不同账号各一条）都要重建。
		s.m.vpnMgr.ForgetPrefix(strconv.FormatInt(prof.ID, 10))
	}
	writeJSON(w, 200, map[string]any{"id": prof.ID})
}

// deleteVPNProfile removes a profile and tears its tunnel down.
func (s *Server) deleteVPNProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	if s.m.vpnMgr != nil {
		s.m.vpnMgr.ForgetPrefix(strconv.FormatInt(id, 10))
	}
	if err := s.m.pg.DeleteVPNProfile(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// startVPNProfile brings a tunnel up ahead of time (the UI "连接" button).
func (s *Server) startVPNProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	if s.m.vpnMgr == nil {
		writeErr(w, 500, vpn.ErrUnsupported.Error())
		return
	}
	prof, err := s.m.pg.VPNProfileByID(id)
	if err != nil || prof == nil {
		writeErr(w, 404, "出口不存在")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = decode(r, &req)
	user, pass := strings.TrimSpace(req.Username), req.Password
	if user == "" {
		user, pass = prof.Username, prof.Password
	}
	if user == "" {
		writeErr(w, 400, "请先填写该项目的 VPN 账号")
		return
	}
	url, err := s.m.vpnMgr.Ensure(r.Context(), vpn.Profile{
		Key: vpnTunnelKey(prof.ID, user),
		ID:  prof.ID, Name: prof.Name, Raw: prof.OVPN,
		Username: user, Password: pass, ExpectEgress: prof.ExpectEgress,
	})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"socks":  url,
		"status": s.m.vpnMgr.Status(vpnTunnelKey(prof.ID, user)),
	})
}

// stopVPNProfile tears a tunnel down.
func (s *Server) stopVPNProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	if s.m.vpnMgr == nil {
		writeJSON(w, 200, map[string]any{})
		return
	}
	// 停掉这条配置下的所有隧道（可能每个项目账号一条）。
	s.m.vpnMgr.ForgetPrefix(strconv.FormatInt(id, 10))
	var tunnels []vpn.Status
	for _, st := range s.m.vpnMgr.Statuses() {
		if st.ID == id {
			tunnels = append(tunnels, st)
		}
	}
	writeJSON(w, 200, map[string]any{"tunnels": tunnels})
}

// setTaskEgress binds a task to an egress ("", "global" or "vpn:<id>").
func (s *Server) setTaskEgress(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	var req struct {
		Egress   string `json:"egress"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	egress := strings.TrimSpace(req.Egress)
	if egress != "" && egress != "global" {
		vpnID, ok := vpnProfileID(egress)
		if !ok {
			writeErr(w, 400, "出口格式应为 vpn:<id>")
			return
		}
		prof, err := s.m.pg.VPNProfileByID(vpnID)
		if err != nil || prof == nil {
			writeErr(w, 400, "出口不存在")
			return
		}
	}
	binding := db.TaskEgress{
		Egress:   egress,
		Username: strings.TrimSpace(req.Username),
		Password: req.Password,
	}
	if err := s.m.pg.SetTaskEgress(id, binding); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 代理是建 agent 时注入的，改出口必须让下一次运行重建 agent。
	s.invalidateTaskAgents()
	resp := map[string]any{"id": id, "egress": egress, "username": binding.Username}
	// 立刻回报这条出口当前的出口 IP，界面不用再等一次请求。
	if st := s.m.vpnMgr.Status(vpnTunnelKey(mustProfileID(egress), binding.Username)); st.State != "" {
		resp["status"] = st
	}
	writeJSON(w, 200, resp)
}

// mustProfileID extracts the profile id from a "vpn:<id>" binding, or 0.
func mustProfileID(egress string) int64 {
	id, _ := vpnProfileID(egress)
	return id
}

// fillTaskEgress 把任务的出口绑定、账号和**当前实际出口 IP** 补进 DTO。
// 出口 IP 读的是隧道实时状态而不是配置值——界面要看到的是"现在真的从哪出去"。
func (s *Server) fillTaskEgress(dto *TaskDTO) {
	if dto == nil || s.m.vpnMgr == nil {
		return
	}
	id, err := strconv.ParseInt(dto.ID, 10, 64)
	if err != nil || id == 0 {
		return
	}
	binding, err := s.m.pg.TaskEgressOf(id)
	if err != nil {
		return
	}
	dto.Egress = binding.Egress
	dto.VPNUsername = binding.Username
	profID, ok := vpnProfileID(binding.Egress)
	if !ok {
		dto.EgressState = vpn.StateStopped
		return
	}
	prof, err := s.m.pg.VPNProfileByID(profID)
	if err != nil || prof == nil {
		dto.EgressLabel = "出口已删除"
		dto.EgressState = vpn.StateError
		return
	}
	dto.EgressLabel = prof.Name
	user := binding.Username
	if user == "" {
		user = prof.Username
	}
	if st := s.m.vpnMgr.Status(vpnTunnelKey(profID, user)); st.State != "" {
		dto.EgressState = st.State
		dto.EgressIP = st.EgressIP
	}
}
