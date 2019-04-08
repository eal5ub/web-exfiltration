package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path"
	"time"
)

type NetworkRequestInterceptedEvent struct {
	EventId   int
	Timestamp time.Time
	EventType string
	PolicyId  string
	TargetId  string

	FrameId             string
	ResourceType        string
	IsNavigationRequest bool
	RedirectURL         string
	Request             *NetworkRequest
	PolicyState         *PolicyState
}

type NetworkRequestWillBeSentEvent struct {
	EventId   int
	Timestamp time.Time
	EventType string
	PolicyId  string
	TargetId  string

	Initiator      *Initiator
	LoaderId       string
	FrameId        string
	HasUserGesture bool
	ResourceType   string
	DocumentURL    string
	Request        *NetworkRequest
	PolicyState    *PolicyState
}

type APIAccessEvent struct {
	EventId   int
	Timestamp time.Time
	EventType string
	PolicyId  string
	TargetId  string

	APIName       string
	ScriptIdStack []string
	PolicyState   *PolicyState
}

type DebuggerScriptParsedEvent struct {
	EventId   int
	Timestamp time.Time
	EventType string
	PolicyId  string
	TargetId  string

	ScriptId   string
	URL        string
	Hash       string
	StackTrace *StackTrace
}

type PageLifecycleEvent struct {
	EventId   int
	Timestamp time.Time
	EventType string
	PolicyId  string
	TargetId  string

	FrameId     string
	LoaderId    string
	Name        string
	PolicyState *PolicyState
}

// Structs used in events.
type NetworkRequest struct {
	URL           string
	Method        string
	HasPostData   bool
	IsLinkPreload bool
}

func NewNetworkRequest(p Message) *NetworkRequest {
	return &NetworkRequest{
		URL:           p.String("url"),
		Method:        p.String("method"),
		HasPostData:   p.Bool("hasPostData"),
		IsLinkPreload: p.Bool("isLinkPreload"),
	}
}

type Initiator struct {
	Type       string
	StackTrace *StackTrace
	URL        string
	LineNumber int
}

func NewInitiator(p Message) *Initiator {
	return &Initiator{
		Type:       p.String("type"),
		StackTrace: NewStackTrace(p.Message("stack")),
		URL:        p.String("url"),
		LineNumber: p.Int("lineNumber"),
	}
}

type StackTrace struct {
	Description string
	CallFrames  []*CallFrame
	Parent      *StackTrace
	ParentId    string
}

func NewStackTrace(p Message) *StackTrace {
	if p == nil {
		return nil
	}

	callFrames := []*CallFrame{}
	for _, cfm := range p.Messages("callFrames") {
		callFrames = append(callFrames, NewCallFrame(cfm))
	}
	return &StackTrace{
		Description: p.String("description"),
		CallFrames:  callFrames,
		Parent:      NewStackTrace(p.Message("parent")),
		ParentId:    p.String("parentId"),
	}
}

type CallFrame struct {
	FunctionName string
	ScriptId     string
	URL          string
	LineNumber   int
	ColumnNumber int
}

func NewCallFrame(p Message) *CallFrame {
	return &CallFrame{
		FunctionName: p.String("functionName"),
		ScriptId:     p.String("scriptId"),
		URL:          p.String("url"),
		LineNumber:   p.Int("lineNumber"),
		ColumnNumber: p.Int("columnNumber"),
	}
}

type PolicyState struct {
	PolicyId    string
	TrustGroups []*TrustGroupState
}

func (s *PolicyState) StackIsTrusted(scriptIdStack []string) bool {
	for _, scriptId := range scriptIdStack {
		tgs := s.TrustGroupStateForScriptId(scriptId)
		if tgs == nil || !tgs.Trusted {
			return false
		}
	}

	return true
}

func (s *PolicyState) TrustGroupStateForScriptId(scriptId string) *TrustGroupState {
	for _, tgs := range s.TrustGroups {
		if tgs.GetRemoteScript(scriptId) != nil || tgs.GetInlineScript(scriptId) != nil {
			return tgs
		}
	}
	return nil
}

type TrustGroupState struct {
	Trusted       bool
	RemoteScripts []*RemoteScript
	InlineScripts []*InlineScript
}

func (s *TrustGroupState) GetRemoteScript(scriptId string) *RemoteScript {
	for _, rs := range s.RemoteScripts {
		if rs.ScriptId == scriptId {
			return rs
		}
	}
	return nil
}

func (s *TrustGroupState) GetInlineScript(scriptId string) *InlineScript {
	for _, is := range s.InlineScripts {
		if is.ScriptId == scriptId {
			return is
		}
	}
	return nil
}

func (cc *ChromeClient) LogEvent(e interface{}) {
	cc.Lock()
	defer cc.Unlock()

	switch v := e.(type) {
	case *NetworkRequestInterceptedEvent:
		v.EventId = cc.nextEventId
	case *NetworkRequestWillBeSentEvent:
		v.EventId = cc.nextEventId
	case *APIAccessEvent:
		v.EventId = cc.nextEventId
	case *DebuggerScriptParsedEvent:
		v.EventId = cc.nextEventId
	case *PageLifecycleEvent:
		v.EventId = cc.nextEventId
	default:
		log.Panic("bad log event type", v)
	}

	cc.eventLog = append(cc.eventLog, e)
	cc.nextEventId += 1
}

func (cc *ChromeClient) WriteLogToFile() {
	b, err := json.MarshalIndent(cc.eventLog, "", "  ")
	if err != nil {
		log.Panic("error marshalling JSON")
	}
	err = ioutil.WriteFile(path.Join(cc.logsDir, "events.json"), b, 0644)
	if err != nil {
		log.Panic("error writing log")
	}
}

func (cc *ChromeClient) NetworkRequestInterceptedLogs(policyId string) []*NetworkRequestInterceptedEvent {
	ret := []*NetworkRequestInterceptedEvent{}

	for _, e := range cc.eventLog {
		if c, ok := e.(*NetworkRequestInterceptedEvent); ok && c.PolicyId == policyId {
			ret = append(ret, c)
		}
	}

	return ret
}

func (cc *ChromeClient) NetworkRequestWillBeSentLogs(policyId string) []*NetworkRequestWillBeSentEvent {
	ret := []*NetworkRequestWillBeSentEvent{}

	for _, e := range cc.eventLog {
		if c, ok := e.(*NetworkRequestWillBeSentEvent); ok && c.PolicyId == policyId {
			ret = append(ret, c)
		}
	}

	return ret
}

func (cc *ChromeClient) APIAccessLogs(policyId string) []*APIAccessEvent {
	ret := []*APIAccessEvent{}

	for _, e := range cc.eventLog {
		if c, ok := e.(*APIAccessEvent); ok && c.PolicyId == policyId {
			ret = append(ret, c)
		}
	}

	return ret
}

func (cc *ChromeClient) DebuggerScriptParsedLogs(policyId string) []*DebuggerScriptParsedEvent {
	ret := []*DebuggerScriptParsedEvent{}

	for _, e := range cc.eventLog {
		if c, ok := e.(*DebuggerScriptParsedEvent); ok && c.PolicyId == policyId {
			ret = append(ret, c)
		}
	}

	return ret
}

func (cc *ChromeClient) PageLifecycleEventLogs(policyId string) []*PageLifecycleEvent {
	ret := []*PageLifecycleEvent{}

	for _, e := range cc.eventLog {
		if c, ok := e.(*PageLifecycleEvent); ok && c.PolicyId == policyId {
			ret = append(ret, c)
		}
	}

	return ret
}
