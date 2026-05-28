package notify

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	To       string `json:"to"`  // comma-separated recipients
	TLS      bool   `json:"tls"` // true = implicit TLS (port 465); false = STARTTLS / plain
}

type Mailer struct {
	cfg SMTPConfig
}

func NewMailer(cfg SMTPConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) Config() SMTPConfig { return m.cfg }

func (m *Mailer) Send(subject, body string) error {
	if m.cfg.Host == "" || m.cfg.To == "" {
		return fmt.Errorf("smtp: host and to are required")
	}
	to := splitTo(m.cfg.To)
	if len(to) == 0 {
		return fmt.Errorf("smtp: no valid recipients")
	}
	msg := buildMsg(m.cfg.From, to, subject, body)
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	if m.cfg.TLS {
		return sendImplicitTLS(addr, m.cfg.Host, auth, m.cfg.From, to, msg)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, to, msg)
}

func (m *Mailer) Test() error {
	return m.Send(
		"[KilasOS] Test notification",
		"This is a test email from KilasOS.\r\n\r\nEmail notifications are configured correctly.",
	)
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

func buildMsg(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func splitTo(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
