package main

import (
	"fmt"
	"log"
	"net/url"
	"sync"

	"github.com/pmezard/adblock/adblock"
)

type TrustGroup struct {
	sync.Mutex
	ScriptSet
	Trusted bool
	Tainted bool
}

type RemoteScript struct {
	ScriptId string
	URL      string
}

type InlineScript struct {
	ScriptId string
	Hash     string
}

type ScriptSet interface {
	AddRemoteScript(scriptId string, scriptURL string)
	AddInlineScript(scriptId string, hash string)
	ContainsRemoteScript(scriptId string, scriptURL string) bool
	ContainsInlineScript(scriptId string, hash string) bool
	RemoteScripts() []*RemoteScript
	InlineScripts() []*InlineScript
}

type UniversalScriptSet struct {
	remoteScripts []*RemoteScript
	inlineScripts []*InlineScript
}

func (ss *UniversalScriptSet) AddRemoteScript(scriptId string, scriptURL string) {
	ss.remoteScripts = append(ss.remoteScripts, &RemoteScript{
		ScriptId: scriptId,
		URL:      scriptURL,
	})
}

func (ss *UniversalScriptSet) AddInlineScript(scriptId string, hash string) {
	ss.inlineScripts = append(ss.inlineScripts, &InlineScript{
		ScriptId: scriptId,
		Hash:     hash,
	})
}

func (ss *UniversalScriptSet) ContainsRemoteScript(scriptId string, scriptURL string) bool {
	return true
}

func (ss *UniversalScriptSet) ContainsInlineScript(scriptId string, hash string) bool {
	return true
}

func (ss *UniversalScriptSet) RemoteScripts() []*RemoteScript {
	return ss.remoteScripts
}

func (ss *UniversalScriptSet) InlineScripts() []*InlineScript {
	return ss.inlineScripts
}

type HostnameScriptSet struct {
	hostnames     []string
	remoteScripts []*RemoteScript
	inlineScripts []*InlineScript
}

func NewHostnameScriptSet(hostnames []string) *HostnameScriptSet {
	return &HostnameScriptSet{
		hostnames: hostnames,
	}
}

func (ss *HostnameScriptSet) AddRemoteScript(scriptId string, scriptURL string) {
	ss.remoteScripts = append(ss.remoteScripts, &RemoteScript{
		ScriptId: scriptId,
		URL:      scriptURL,
	})
}

func (ss *HostnameScriptSet) AddInlineScript(scriptId string, hash string) {
	ss.inlineScripts = append(ss.inlineScripts, &InlineScript{
		ScriptId: scriptId,
		Hash:     hash,
	})
}

func (ss *HostnameScriptSet) ContainsRemoteScript(scriptId string, scriptURL string) bool {
	u, err := url.Parse(scriptURL)
	if err != nil {
		return false
	}

	for _, h := range ss.hostnames {
		origin := fmt.Sprintf("%v://%v", u.Scheme, u.Host)
		if h == origin {
			return true
		}
	}
	return false
}

func (ss *HostnameScriptSet) ContainsInlineScript(scriptId string, hash string) bool {
	return true
}

func (ss *HostnameScriptSet) RemoteScripts() []*RemoteScript {
	return ss.remoteScripts
}

func (ss *HostnameScriptSet) InlineScripts() []*InlineScript {
	return ss.inlineScripts
}

type FilterListScriptSet struct {
	filters       []string
	remoteScripts []*RemoteScript
	inlineScripts []*InlineScript
	matcher       *adblock.RuleMatcher
}

var cachedMatcher *adblock.RuleMatcher

func NewFilterListScriptSet() *FilterListScriptSet {
	if cachedMatcher == nil {
		m, _, err := adblock.NewMatcherFromFiles("filter_lists/easylist.txt", "filter_lists/easyprivacy.txt")
		if err != nil {
			log.Panic(err)
		}
		cachedMatcher = m
	}
	return &FilterListScriptSet{
		matcher: cachedMatcher,
	}
}

func (ss *FilterListScriptSet) AddRemoteScript(scriptId string, scriptURL string) {
	ss.remoteScripts = append(ss.remoteScripts, &RemoteScript{
		ScriptId: scriptId,
		URL:      scriptURL,
	})
}

func (ss *FilterListScriptSet) AddInlineScript(scriptId string, hash string) {
	ss.inlineScripts = append(ss.inlineScripts, &InlineScript{
		ScriptId: scriptId,
		Hash:     hash,
	})
}

func (ss *FilterListScriptSet) ContainsRemoteScript(scriptId string, scriptURL string) bool {
	matched, _, err := ss.matcher.Match(&adblock.Request{
		URL: scriptURL,
	})
	if err != nil {
		log.Println(err)
		return false
	}
	return matched
}

func (ss *FilterListScriptSet) ContainsInlineScript(scriptId string, hash string) bool {
	return false
}

func (ss *FilterListScriptSet) RemoteScripts() []*RemoteScript {
	return ss.remoteScripts
}

func (ss *FilterListScriptSet) InlineScripts() []*InlineScript {
	return nil
}
