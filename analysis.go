package main

import (
	"log"
	"strings"
)

type PolicyAnalysis struct {
	PolicyId       string
	Description    string
	PolicyViolated bool

	TaintingAPIName string

	ReqResourceType string
	ReqURL          string
	ReqInitiator    string
	ReqStackScripts []string
}

func (cc *ChromeClient) AnalyzeLogs() []PolicyAnalysis {
	ret := []PolicyAnalysis{}
	for _, pid := range cc.policyIds {
		pa := cc.AnalyzePolicy(pid)

		// Skip debug pages and Chrome internal pages.
		if pa.Description == "" || pa.Description == cc.WebServerURL("/") || pa.Description == cc.WebServerURL("/launched") || strings.HasPrefix(pa.Description, cc.WebServerURL("/event_log")) || strings.HasPrefix(pa.Description, "chrome") {
			continue
		}
		ret = append(ret, pa)
	}
	return ret
}
func (cc *ChromeClient) AnalyzePolicy(pid string) PolicyAnalysis {
	cc.Lock()
	defer cc.Unlock()

	pa := PolicyAnalysis{
		PolicyId: pid,
	}

	presendLogs := cc.NetworkRequestWillBeSentLogs(pid)
	if len(presendLogs) == 0 {
		return pa
	}
	pa.Description = presendLogs[0].DocumentURL

	// Check if the untrusted trust group was tainted.
	apiLogs := cc.APIAccessLogs(pid)
	var taintingEvent *APIAccessEvent
	for _, e := range apiLogs {
		if strings.HasPrefix(e.APIName, "exfiltration_") {
			continue
		}

		if e.PolicyState.StackIsTrusted(e.ScriptIdStack) {
			continue
		}
		taintingEvent = e
		pa.TaintingAPIName = e.APIName
		break
	}

	if taintingEvent == nil {
		return pa
	}

	// Check for potential exfiltration in NetworkRequestWillBeSentLogs.
	exfiltrationEventId := 0
	for _, e := range presendLogs {
		if e.Initiator == nil || e.Initiator.StackTrace == nil {
			continue
		}

		if e.EventId > taintingEvent.EventId {
			reqStackScripts := []string{}
			stackTrusted := true
			if e.Initiator.StackTrace != nil {
				cfv := e.Initiator.StackTrace.CallFrames
				if len(cfv) == 0 && e.Initiator.StackTrace.Parent != nil {
					cfv = e.Initiator.StackTrace.Parent.CallFrames
				}
				for _, cf := range cfv {
					tgs := e.PolicyState.TrustGroupStateForScriptId(cf.ScriptId)
					if tgs != nil {
						stackTrusted = stackTrusted && tgs.Trusted
					} else {
						log.Println("Unknown script ID", cf.ScriptId)
					}
					reqStackScripts = append(reqStackScripts, cf.ScriptId)
				}
			}

			if stackTrusted {
				continue
			}

			exfiltrationEventId = e.EventId
			pa.PolicyViolated = true
			pa.ReqInitiator = e.Initiator.Type
			pa.ReqResourceType = e.ResourceType
			pa.ReqURL = e.Request.URL
			pa.ReqStackScripts = reqStackScripts
			break
		}
	}

	// Check for potential earlier exfiltration in APIAccessLogs.
	for _, e := range apiLogs {
		if !strings.HasPrefix(e.APIName, "exfiltration_") {
			continue
		}

		if e.PolicyState.StackIsTrusted(e.ScriptIdStack) {
			continue
		}

		if e.EventId > taintingEvent.EventId && (!pa.PolicyViolated || e.EventId < exfiltrationEventId) {
			exfiltrationEventId = e.EventId
			pa.PolicyViolated = true
			pa.ReqResourceType = "Document"
			pa.ReqInitiator = "script"
			pa.ReqStackScripts = e.ScriptIdStack
			break
		}
	}

	// Check for potential earlier exfiltration in NetworkRequetWillBeSentLogs
	// for targets created by scripts.
	for _, otherPid := range cc.policyIds {
		otherPresendLogs := cc.NetworkRequestWillBeSentLogs(otherPid)
		if len(otherPresendLogs) == 0 {
			continue
		}
		e := otherPresendLogs[0]
		if e.EventId > taintingEvent.EventId &&
			(!pa.PolicyViolated || e.EventId < exfiltrationEventId) &&
			e.Initiator != nil &&
			e.Initiator.StackTrace != nil {

			reqStackScripts := []string{}
			stackTrusted := true

			if len(apiLogs) > 0 {
				policyState := apiLogs[len(apiLogs)-1].PolicyState
				cfv := e.Initiator.StackTrace.CallFrames
				if len(cfv) == 0 && e.Initiator.StackTrace.Parent != nil {
					cfv = e.Initiator.StackTrace.Parent.CallFrames
				}
				for _, cf := range cfv {
					tgs := policyState.TrustGroupStateForScriptId(cf.ScriptId)
					stackTrusted = stackTrusted && (tgs != nil && tgs.Trusted)
					reqStackScripts = append(reqStackScripts, cf.ScriptId)
				}
			}

			if stackTrusted {
				continue
			}

			exfiltrationEventId = e.EventId
			pa.PolicyViolated = true
			pa.ReqResourceType = e.ResourceType
			pa.ReqInitiator = e.Initiator.Type
			pa.ReqURL = e.Request.URL
			pa.ReqStackScripts = reqStackScripts
			break
		}
	}

	return pa
}
