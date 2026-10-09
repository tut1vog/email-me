package dashboard

import (
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/tut1vog/email-me/internal/admin"
)

// The Password page sets the admin password. A session opened with a setup
// password reaches only this page until it has chosen one; otherwise the
// current password is asked for too.

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	s.renderPassword(w, r, http.StatusOK, safeNext(r.URL.Query().Get("next")), "")
}

func (s *Server) renderPassword(w http.ResponseWriter, r *http.Request, status int, next, errMsg string) {
	setup := sessionFrom(r).MustChange()
	title := "Change password"
	if setup {
		title = "Choose a password"
	}
	s.renderStatus(w, r, status, "password", title, map[string]any{
		"Setup": setup, "Next": next, "Error": errMsg, "MinLength": admin.MinLength,
	})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	f := r.PostForm
	next := safeNext(f.Get("next"))
	pw := f.Get("password")
	switch {
	case pw != f.Get("confirm"):
		s.renderPassword(w, r, http.StatusUnprocessableEntity, next, "The new passwords do not match.")
		return
	case utf8.RuneCountInString(pw) < admin.MinLength:
		s.renderPassword(w, r, http.StatusUnprocessableEntity, next, fmt.Sprintf("Choose a password of at least %d characters.", admin.MinLength))
		return
	}
	ip := clientIP(r)
	setup := sess.MustChange()
	if !setup {
		// The current password is a login: it shares the login throttle.
		if ok, wait := s.throttle.Begin(ip); !ok {
			s.renderPassword(w, r, http.StatusTooManyRequests, next, fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(wait.Seconds())+1))
			return
		}
		ok, _, err := s.verifyPassword(r.Context(), f.Get("current"))
		if err != nil {
			s.fail(w, "checking the admin password", err)
			return
		}
		if !ok {
			s.Log.Warn("dashboard password change: wrong current password", "ip", ip)
			s.renderPassword(w, r, http.StatusUnprocessableEntity, next, "The current password is wrong.")
			return
		}
		s.throttle.Success(ip)
	}
	same, _, err := s.verifyPassword(r.Context(), pw)
	if err != nil {
		s.fail(w, "checking the admin password", err)
		return
	}
	if same {
		s.renderPassword(w, r, http.StatusUnprocessableEntity, next, "Choose a password different from the current one.")
		return
	}
	if err := admin.Set(r.Context(), s.Store, pw); err != nil {
		s.fail(w, "saving the admin password", err)
		return
	}
	s.sessions.DeleteOthers(sess.ID)
	sess.SetMustChange(false)
	s.Log.Info("dashboard admin password changed", "ip", ip, "setup", setup)
	if setup {
		s.flash(r, "ok", "Password set. Use it from now on; the setup password no longer works.")
	} else {
		s.flash(r, "ok", "Password changed. Every other session was logged out.")
	}
	s.redirect(w, r, next)
}
