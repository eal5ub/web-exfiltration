package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/ethanal/godet"
)

const (
	policyTypeTrusting = iota
	policyTypeUntrusting
	policyTypeHostname
	policyTypeFilterList
	policyTypeInvalid
)

type Policy struct {
	// trustGroups are in the order they will be evaluated. A script is
	// classified in the first trustGroup that accepts it.
	Id          string
	trustGroups []*TrustGroup
}

func newPolicyId() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic(err)
	}
	ret := hex.EncodeToString(b)
	return ret
}

func (p *Policy) RegisterRemoteScript(scriptId string, scriptURL string, st *StackTrace) *TrustGroup {
	if st != nil {
		for _, cf := range st.CallFrames {
			tg := p.TrustGroupForScriptId(cf.ScriptId)
			if tg != nil && !tg.Trusted {
				tg.AddRemoteScript(scriptId, scriptURL)
				return tg
			}
		}
	}

	for _, tg := range p.trustGroups {
		if tg.ContainsRemoteScript(scriptId, scriptURL) {
			tg.AddRemoteScript(scriptId, scriptURL)
			return tg
		}
	}
	return nil
}

func (p *Policy) RegisterInlineScript(scriptId string, hash string, st *StackTrace) *TrustGroup {
	if st != nil {
		for _, cf := range st.CallFrames {
			tg := p.TrustGroupForScriptId(cf.ScriptId)
			if tg != nil && !tg.Trusted {
				tg.AddInlineScript(scriptId, hash)
				return tg
			}
		}
	}

	for _, tg := range p.trustGroups {
		if tg.ContainsInlineScript(scriptId, hash) {
			tg.AddInlineScript(scriptId, hash)
			return tg
		}
	}
	return nil
}

func (p *Policy) TrustGroupForScriptId(scriptId string) *TrustGroup {
	for _, tg := range p.trustGroups {
		for _, s := range tg.RemoteScripts() {
			if s.ScriptId == scriptId {
				return tg
			}
		}

		for _, s := range tg.InlineScripts() {
			if s.ScriptId == scriptId {
				return tg
			}
		}
	}

	return nil
}

func (p *Policy) TrustedGroup() *TrustGroup {
	for _, tg := range p.trustGroups {
		if tg.Trusted {
			return tg
		}
	}

	return nil
}

func (p *Policy) UntrustedGroup() *TrustGroup {
	for _, tg := range p.trustGroups {
		if !tg.Trusted {
			return tg
		}
	}

	return nil
}

func (p *Policy) TrustedScriptIds() []string {
	tg := p.TrustedGroup()
	if tg == nil {
		return nil
	}

	ret := []string{}

	for _, s := range tg.RemoteScripts() {
		ret = append(ret, s.ScriptId)
	}
	for _, s := range tg.InlineScripts() {
		ret = append(ret, s.ScriptId)
	}

	return ret
}

func (p *Policy) State() *PolicyState {
	ret := &PolicyState{
		PolicyId: p.Id,
	}

	for _, tg := range p.trustGroups {
		ret.TrustGroups = append(ret.TrustGroups, &TrustGroupState{
			Trusted:       tg.Trusted,
			RemoteScripts: tg.RemoteScripts(),
			InlineScripts: tg.InlineScripts(),
		})
	}
	return ret
}

func NewTrustingPolicy() *Policy {
	return &Policy{
		Id: newPolicyId(),
		trustGroups: []*TrustGroup{
			&TrustGroup{
				ScriptSet: &UniversalScriptSet{},
				Trusted:   true,
			},
		},
	}
}

func NewUntrustingPolicy() *Policy {
	return &Policy{
		Id: newPolicyId(),
		trustGroups: []*TrustGroup{
			&TrustGroup{
				ScriptSet: &UniversalScriptSet{},
				Trusted:   false,
			},
		},
	}
}

func NewHostnamePolicy(hosts []string) *Policy {
	return &Policy{
		Id: newPolicyId(),
		trustGroups: []*TrustGroup{
			&TrustGroup{
				ScriptSet: NewHostnameScriptSet(hosts),
				Trusted:   true,
			},
			&TrustGroup{
				ScriptSet: &UniversalScriptSet{},
				Trusted:   false,
			},
		},
	}
}

func NewFilterListPolicy() *Policy {
	return &Policy{
		Id: newPolicyId(),
		trustGroups: []*TrustGroup{
			&TrustGroup{
				ScriptSet: NewFilterListScriptSet(),
				Trusted:   false,
			},
			&TrustGroup{
				ScriptSet: &UniversalScriptSet{},
				Trusted:   true,
			},
		},
	}
}

// The Chrome Remote Debugger API doesn't currently give us a way to correlate
// requestIds and interceptionIds, so we match them up using as many details of
// the request as are available. In practice, this works well enough.
type RequestIdentifier struct {
	FrameId string
	Request Message
}

type Target struct {
	*godet.RemoteDebugger
	// godet.RemoteDebugger has it's own embedded mutex, so we need a named mutex.
	mutex                   sync.Mutex
	chromeClient            *ChromeClient
	TargetId                string
	NavHistory              []string
	Policy                  *Policy
	instrumentationScriptId string
}

func NewTarget(cc *ChromeClient, targetId string, url string) *Target {
	log.Println("NewTarget:", targetId)
	c, err := godet.Connect(fmt.Sprintf("localhost:%v", remoteDebuggingPort), verbose)
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.SendRequest("Target.activateTarget", godet.Params{
		"targetId": targetId,
	})

	t := &Target{
		RemoteDebugger: c,
		TargetId:       targetId,
		chromeClient:   cc,
	}
	t.navReset(url)

	t.mutex.Lock()
	defer t.mutex.Unlock()

	_, err = t.SendRequest("Network.setRequestInterception", godet.Params{
		"patterns": []godet.Params{{
			"urlPattern": "http*",
		}},
	})
	if err != nil {
		log.Fatal(err)
	}

	cbm := map[string]func(Message){
		"Debugger.scriptParsed":      t.debuggerScriptParsed,
		"Debugger.paused":            t.debuggerPaused,
		"Network.requestIntercepted": t.networkRequestIntercepted,
		"Network.requestWillBeSent":  t.networkRequestWillBeSent,
		"Runtime.consoleAPICalled":   t.runtimeConsoleAPICalled,
		"Page.lifecycleEvent":        t.chromeClient.pageLifecycleEvent,
	}

	for method, cb := range cbm {
		t.chromeClient.setCallback(c, method, cb)
	}

	t.chromeClient.initConn(c)

	t.initTarget()

	t.chromeClient.SignalAttached()
	return t
}

func (t *Target) initTarget() {
	_, err := t.SendRequest("Debugger.setAsyncCallStackDepth", godet.Params{
		"maxDepth": 32,
	})
	if err != nil {
		log.Panic(err)
	}

	_, err = t.SendRequest("Page.addScriptToEvaluateOnNewDocument", godet.Params{
		"source": "debugger;",
	})
	if err != nil {
		log.Panic(err)
	}

	t.installInstrumentation()
}

func (t *Target) navReset(pageURL string) {
	t.NavHistory = append(t.NavHistory, pageURL)
	t.instrumentationScriptId = ""

	switch t.chromeClient.policyType {
	case policyTypeTrusting:
		t.Policy = NewTrustingPolicy()
	case policyTypeUntrusting:
		t.Policy = NewUntrustingPolicy()
	case policyTypeHostname:
		u, err := url.Parse(pageURL)
		if err != nil {
			log.Panic(err)
		}
		origin := fmt.Sprintf("%v://%v", u.Scheme, u.Host)
		t.Policy = NewHostnamePolicy([]string{origin})
	case policyTypeFilterList:
		t.Policy = NewFilterListPolicy()
	default:
		log.Panic("bad policyType: this should have been checked in init()")
	}

	t.chromeClient.policyIds = append(t.chromeClient.policyIds, t.Policy.Id)
}

func (t *Target) installInstrumentation() {
	if t.instrumentationScriptId == "" {
		r, err := t.SendRequest("Runtime.compileScript", godet.Params{
			"expression":    t.chromeClient.instrumentationScript,
			"sourceURL":     "",
			"persistScript": true,
		})
		if err != nil {
			log.Panic(err)
		}
		scriptId := Message(r).String("scriptId")
		if scriptId == "" {
			log.Panic(fmt.Errorf("%v", r))
		}

		t.instrumentationScriptId = scriptId

		_, err = t.SendRequest("Runtime.runScript", godet.Params{
			"scriptId": t.instrumentationScriptId,
		})
		if err != nil {
			log.Panic(err)
		}
	}
}

func (t *Target) PauseDebugger() {
	return
	_, err := t.SendRequest("Debugger.pause", nil)
	if err != nil {
		log.Panic(err)
	}
}

func (t *Target) networkRequestIntercepted(p Message) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	nav := p.Bool("isNavigationRequest")
	navStr := ""
	if nav {
		navStr = " Navigation"
	}
	url := p.Message("request").String("url")
	resourceType := p.String("resourceType")
	log.Printf("Intercepted%v [%v]: %v", navStr, resourceType, url)

	if t.TargetId != p.String("frameId") {
		// We only consider top-level navs.
		nav = false
	}

	if nav {
		t.navReset(url)
	}

	iid := p.String("interceptionId")
	_, err := t.SendRequest("Network.continueInterceptedRequest", godet.Params{
		"interceptionId": iid,
	})
	if err != nil {
		log.Panic(err)
	}

	t.chromeClient.LogEvent(&NetworkRequestInterceptedEvent{
		Timestamp:           time.Now(),
		EventType:           "NetworkRequestIntercepted",
		PolicyId:            t.Policy.Id,
		TargetId:            t.TargetId,
		FrameId:             p.String("frameId"),
		ResourceType:        p.String("type"),
		IsNavigationRequest: nav,
		RedirectURL:         p.String("redirectURL"),
		Request:             NewNetworkRequest(p.Message("request")),
		PolicyState:         t.Policy.State(),
	})
}

func (t *Target) networkRequestWillBeSent(p Message) {
	initiator := NewInitiator(p.Message("initiator"))
	scriptIds := []string{}
	if initiator != nil && initiator.StackTrace != nil {
		callFrames := initiator.StackTrace.CallFrames
		if len(callFrames) == 0 {
			callFrames = initiator.StackTrace.Parent.CallFrames
		}
		for _, cf := range callFrames {
			scriptIds = append(scriptIds, cf.ScriptId)
		}
	}
	req := p.Message("request")
	reqURL := req.String("url")
	log.Println("Request:", reqURL, scriptIds)

	t.chromeClient.LogEvent(&NetworkRequestWillBeSentEvent{
		Timestamp:      time.Unix(int64(p.Int("wallTime")), 0),
		EventType:      "NetworkRequestWillBeSent",
		PolicyId:       t.Policy.Id,
		TargetId:       t.TargetId,
		Initiator:      initiator,
		LoaderId:       p.String("loaderId"),
		FrameId:        p.String("frameId"),
		HasUserGesture: p.Bool("hasUserGesture"),
		ResourceType:   p.String("type"),
		DocumentURL:    p.String("documentURL"),
		Request:        NewNetworkRequest(req),
		PolicyState:    t.Policy.State(),
	})
}

func (t *Target) runtimeConsoleAPICalled(p Message) {
	if chromiumLog {
		return
	}
	s := fmt.Sprintf("console.%v:", p.String("type"))
	for _, a := range p["args"].([]interface{}) {
		arg := a.(map[string]interface{})
		if v := arg["value"]; v != nil || arg["subtype"] == "null" {
			s = fmt.Sprintf("%v %v", s, v)
		} else {
			s = fmt.Sprintf("%v <%v>", s, arg["type"])
		}
	}
	log.Println(s)
}

func (t *Target) debuggerScriptParsed(p Message) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if p.Bool("isLiveEdit") {
		return
	}

	st := NewStackTrace(p.Message("stackTrace"))
	if st != nil {
		// Ignore scripts that originate from the instrumentation code.
		ignoreScript := true
		for _, cf := range st.CallFrames {
			if cf.ScriptId != t.instrumentationScriptId {
				ignoreScript = false
			}
		}
		if ignoreScript {
			return
		}
	}

	scriptId := p.String("scriptId")
	log.Println("Parsed:", scriptId)
	t.chromeClient.LogEvent(&DebuggerScriptParsedEvent{
		Timestamp:  time.Now(),
		EventType:  "DebuggerScriptParsed",
		PolicyId:   t.Policy.Id,
		TargetId:   t.TargetId,
		ScriptId:   p.String("scriptId"),
		URL:        p.String("url"),
		Hash:       p.String("hash"),
		StackTrace: NewStackTrace(p.Message("stackTrace")),
	})

	// hasSourceURL doesn't appear to indicate whether the script is remote.
	isRemote := (p.Int("startLine") == 0) && (p.Int("startColumn") == 0) && p.String("url") != ""
	if isRemote {
		tg := t.Policy.RegisterRemoteScript(scriptId, p.String("url"), st)
		if tg == nil {
			log.Println("Failed to register remote script:", scriptId, p.String("url"))
		}
	} else {
		tg := t.Policy.RegisterInlineScript(scriptId, p.String("hash"), st)
		if tg == nil {
			log.Println("Failed to register inline script:", scriptId, p.String("hash"))
		}
	}
}

func (t *Target) debuggerPaused(p Message) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	callFrames := p.Messages("callFrames")
	scriptIds := []string{}
	for _, cf := range callFrames {
		scriptIds = append(scriptIds, cf.Message("location").String("scriptId"))
	}

	reason := p.String("reason")
	reasonStr := reason

	t.installInstrumentation()
	if reason == "EventListener" {
		eventName := p.Message("data").String("eventName")
		reasonStr = fmt.Sprintf("%v:%v", reason, eventName)
	} else if scriptIds[0] == t.instrumentationScriptId {
		reasonStr = callFrames[0].String("functionName")

		trustedScriptIds := godet.Params{}
		for _, sid := range t.Policy.TrustedScriptIds() {
			trustedScriptIds[sid] = true
		}

		_, err := t.SendRequest("Debugger.setVariableValue", godet.Params{
			"scopeNumber":  1,
			"variableName": "trustedScriptIds",
			"newValue": godet.Params{
				"value": trustedScriptIds,
			},
			"callFrameId": callFrames[0].String("callFrameId"),
		})
		if err != nil {
			log.Panic(err)
		}

		if strings.HasPrefix(reasonStr, "shim_") {
			t.chromeClient.LogEvent(&APIAccessEvent{
				Timestamp:     time.Now(),
				EventType:     "APIAccess",
				PolicyId:      t.Policy.Id,
				TargetId:      t.TargetId,
				APIName:       strings.TrimPrefix(reasonStr, "shim_"),
				ScriptIdStack: scriptIds,
				PolicyState:   t.Policy.State(),
			})
		}
	} else {
		reasonStr = "breakpoint"
	}

	log.Printf("Paused [%v]: call stack: %v", reasonStr, scriptIds)

	_, err := t.SendRequest("Debugger.resume", godet.Params{})
	if err != nil {
		log.Panic(err)
	}
}

type JavaScriptShim struct {
	Name     string
	Object   string
	Property string
}

func (cc *ChromeClient) initInstrumentationScript() {
	// This needs to be templated so we can get "dynamic" values in the stack
	// trace so the debugger can easily know what shim it's paused on. One
	// alternative is declaring functions dynamically using eval, but that
	// creates many VMs, making it more complicated to tell whether a stack frame
	// is part of the instrumentation script.
	shims := []JavaScriptShim{}

	f, err := os.Open("js/shims.txt")
	if err != nil {
		log.Panic(err)
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		s.Text()
		tokens := strings.Fields(s.Text())
		if len(tokens) != 3 {
			log.Panic("bad line in shim file")
		}
		shims = append(shims, JavaScriptShim{
			Name:     tokens[0],
			Object:   tokens[1],
			Property: tokens[2],
		})
	}

	t := template.Must(template.ParseFiles("js/instrumentation_template.js"))
	b := &bytes.Buffer{}
	err = t.Execute(b, shims)
	if err != nil {
		log.Panic(err)
	}
	cc.instrumentationScript = b.String()
}
