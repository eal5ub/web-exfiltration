package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
)

func listFlags() map[string]flag.Value {
	ret := make(map[string]flag.Value)

	flag.VisitAll(func(f *flag.Flag) {
		ret[f.Name] = f.Value
	})

	return ret
}

func activePolicyType(cc *ChromeClient) string {
	pre := fmt.Sprintf("Policy %v: ", cc.policyType)

	switch cc.policyType {
	case policyTypeTrusting:
		return pre + "Trust everything"
	case policyTypeUntrusting:
		return pre + "Trust nothing"
	case policyTypeHostname:
		return pre + "Trust hostname matching page origin"
	case policyTypeFilterList:
		return pre + "Distrust ad/analytics scripts"
	default:
		log.Panic("bad policyType: this should have been checked in init()")
		return ""
	}
}

func testServerURL(path string) string {
	return fmt.Sprintf("http://localhost:%v%v", webServerPort, path)
}

func testServerRedirectURL(path string) string {
	return testServerURL(fmt.Sprintf("/redirect?path=%v", url.QueryEscape(path)))
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, testServerURL(r.FormValue("path")), http.StatusFound)
}

type HomeHandler struct {
	chromeClient *ChromeClient
	template     *template.Template
}

func NewHomeHandler(cc *ChromeClient) HomeHandler {
	h := HomeHandler{
		chromeClient: cc,
	}
	h.parseTemplates()
	return h
}

func (h *HomeHandler) parseTemplates() {
	h.template = template.Must(template.ParseFiles("templates/base.html", "templates/home.html"))
}

type HomeTemplateContext struct {
	TestHandlers []TestHandler
	Flags        map[string]flag.Value
	ActivePolicy string
	ChromeClient *ChromeClient
}

func (h HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.parseTemplates()

	c := HomeTemplateContext{
		TestHandlers: testHandlers,
		Flags:        listFlags(),
		ActivePolicy: activePolicyType(h.chromeClient),
		ChromeClient: h.chromeClient,
	}
	err := h.template.ExecuteTemplate(w, "base", c)
	if err != nil {
		log.Panic(err)
	}
}

type LogsHandler struct {
	chromeClient *ChromeClient
	template     *template.Template
}

func NewLogsHandler(cc *ChromeClient) LogsHandler {
	h := LogsHandler{
		chromeClient: cc,
	}
	h.parseTemplates()
	return h
}

func (h *LogsHandler) parseTemplates() {
	funcMap := template.FuncMap{
		"json": func(s interface{}) string {
			b, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return err.Error()
			}
			return string(b)
		},
	}
	h.template = template.Must(template.New("base").Funcs(funcMap).ParseFiles("templates/base.html", "templates/logs.html"))
}

type LogsTemplateContext struct {
	ChromeClient *ChromeClient
	PolicyId     string
}

func (h LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.parseTemplates()

	c := LogsTemplateContext{
		ChromeClient: h.chromeClient,
		PolicyId:     r.URL.Query().Get("policy"),
	}
	err := h.template.ExecuteTemplate(w, "base", c)
	if err != nil {
		log.Panic(err)
	}
}

func (cc *ChromeClient) initTestServer() *http.Server {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("static"))

	mux.HandleFunc("/launched", func(w http.ResponseWriter, r *http.Request) {
		cc.WaitAttached()
		cc.SignalReady()
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/redirect", redirectHandler)
	mux.Handle("/event_log", NewLogsHandler(cc))
	mux.Handle("/", NewHomeHandler(cc))

	for _, th := range testHandlers {
		mux.Handle(th.Path, th)
	}

	srv := &http.Server{Addr: fmt.Sprintf(":%d", webServerPort), Handler: mux}
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		err := srv.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	return srv
}
