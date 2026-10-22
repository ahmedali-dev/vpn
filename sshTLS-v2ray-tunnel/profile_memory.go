package main

import "net/url"

func credentialsRemoved(args []string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		switch out[i] {
		case "-tun", "-auto-route", "-ssh-trust-on-first-use":
			continue
		}
		if i+1 >= len(out) {
			break
		}
		switch out[i] {
		case "-p", "-u", "-v2ray-uuid", "-v2ray-link":
			out[i+1] = ""
		case "-proxy":
			if u, err := url.Parse(out[i+1]); err == nil {
				u.User = nil
				out[i+1] = u.String()
			}
		}
		i++
	}
	return out
}
func (s *profileStore) cacheProfile(p savedProfile) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.session == nil {
		s.session = map[int64][]string{}
	}
	if p.SessionOnly {
		s.session[p.ID] = append([]string(nil), p.Args...)
	} else {
		delete(s.session, p.ID)
	}
}
func (s *profileStore) restoreSession(p *savedProfile) {
	if !p.SessionOnly {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if args, ok := s.session[p.ID]; ok {
		p.Args = append([]string(nil), args...)
	} else {
		p.NeedsCredentials = true
	}
}
