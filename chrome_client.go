package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethanal/godet"
)

type ChromeClient struct {
	sync.RWMutex
	runDir                string
	ready                 chan struct{}
	attached              chan struct{}
	shutdown              chan error
	stopped               chan error
	rootConn              *godet.RemoteDebugger
	targets               map[string]*Target
	firstAttach           sync.Once
	policyType            int
	eventLog              []interface{}
	nextEventId           int
	policyIds             []string
	instrumentationScript string
	watchedTargets        []string
	logsDir               string
}

func NewChromeClient(runDir string, policyType int) *ChromeClient {
	cc := &ChromeClient{
		runDir:     runDir,
		policyType: policyType,
		ready:      make(chan struct{}),
		attached:   make(chan struct{}),
		shutdown:   make(chan error),
		stopped:    make(chan error),
		targets:    make(map[string]*Target),
	}

	cc.initInstrumentationScript()
	srv := cc.initTestServer()

	userDataDir, err := filepath.Abs(path.Join(runDir, "user_data"))
	if err != nil {
		log.Fatal(err)
	}
	extensionDir, err := filepath.Abs("extension")
	if err != nil {
		log.Fatal(err)
	}
	logsDir, err := filepath.Abs(path.Join(runDir, "logs"))
	if err != nil {
		log.Fatal(err)
	}
	cc.logsDir = logsDir

	os.RemoveAll(userDataDir)
	os.MkdirAll(path.Join(userDataDir, "Default"), os.ModePerm)
	b := []byte(`
		{
			"devtools": {
				"preferences": {
					"currentDockState": "\"bottom\"",
					"Inspector.drawerSplitViewState": "{\"horizontal\":{\"size\":0,\"showMode\":\"OnlyMain\"}}",
					"InspectorView.splitViewState": "{\"vertical\":{\"size\":0},\"horizontal\":{\"size\":73}}",
					"disablePausedStateOverlay": "true"
				}
			},
			"extensions": {
				"ui": {
					"developer_mode": true
				}
			}
		}
	`)
	err = ioutil.WriteFile(path.Join(userDataDir, "Default/Preferences"), b, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	executable := chromiumPath
	flags := []string{
		fmt.Sprintf("--remote-debugging-port=%v", remoteDebuggingPort),
		"--enable-logging=stderr",
		"--v=0",
		"--disable-fre",
		"--no-default-browser-check",
		"--no-first-run",
		"--disable-popup-blocking",
		"--enable-devtools-experiments",
		fmt.Sprintf("--load-extension=%v", extensionDir),
		fmt.Sprintf("--user-data-dir=%v", userDataDir),
	}
	if headless {
		flags = append(flags, []string{
			"--disable-gpu",
			"--window-size=1366,3840",
		}...)

		// Headless mode isn't quite reliable, so we use xvfb-run.
		executable = "xvfb-run"
		flags = append([]string{"-a", chromiumPath}, flags...)
	}
	if openDevTools {
		flags = append(flags, "--auto-open-devtools-for-tabs")
	}

	flags = append(flags, cc.WebServerURL("/launched"))

	cmd := exec.Command(executable, flags...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if chromiumLog {
		cmdStdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		go pipeToLog(cmdStdout)

		cmdStderr, err := cmd.StderrPipe()
		if err != nil {
			log.Fatal(err)
		}
		go pipeToLog(cmdStderr)
	}

	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		cmd.Process.Wait()
		cc.shutdown <- nil
	}()

	go func() {
		shutdownErr := <-cc.shutdown
		log.Println("Shutting down...")
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		log.Println("Chromium stopped.")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		log.Println("Server stopped.")
		time.AfterFunc(2*time.Second, func() {
			log.Println("Shutdown timed out")
		})
		cc.stopped <- shutdownErr
	}()

	cc.setupRootConn()
	return cc
}

func (cc *ChromeClient) WebServerURL(path string) string {
	return fmt.Sprintf("http://localhost:%v%v", webServerPort, path)
}

func (cc *ChromeClient) WaitAttached() {
	<-cc.attached
}

func (cc *ChromeClient) SignalAttached() {
	cc.firstAttach.Do(func() {
		cc.attached <- struct{}{}
	})
}

func (cc *ChromeClient) SignalReady() {
	cc.ready <- struct{}{}
}

func (cc *ChromeClient) WaitReady() {
	<-cc.ready
}

func (cc *ChromeClient) WaitStopped() error {
	return <-cc.stopped
}

func (cc *ChromeClient) Shutdown(err error) {
	cc.shutdown <- err
}

func (cc *ChromeClient) Recover() error {
	x := recover()
	if x != nil {
		debug.PrintStack()
		err := fmt.Errorf("Recovered panic: %v", x)
		cc.shutdown <- err
		return err
	}
	return nil
}

func (cc *ChromeClient) getTarget(targetURL string) *Target {
	for _, t := range cc.targets {
		for _, u := range t.NavHistory {
			if u == targetURL {
				return t
			}
		}
	}
	return nil
}

func enableDomainEvents(c *godet.RemoteDebugger) {
	c.DomainEvents("Debugger", true)
	c.DomainEvents("Network", true)
	c.DomainEvents("Page", true)
	c.DomainEvents("Runtime", true)
	c.DomainEvents("Target", true)
	c.DomainEvents("Inspector", true)
}

func (cc *ChromeClient) initConn(c *godet.RemoteDebugger) {
	_, err := c.SendRequest("Target.setDiscoverTargets", godet.Params{
		"discover": true,
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.SendRequest("Target.setAutoAttach", godet.Params{
		"autoAttach":             true,
		"waitForDebuggerOnStart": false,
	})
	if err != nil {
		log.Fatal(err)
	}

	cc.setCallback(c, "Target.attachedToTarget", func(m Message) {
		enableDomainEvents(c)
	})

	_, err = c.SendRequest("Network.setCacheDisabled", godet.Params{
		"cacheDisabled": true,
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.SendRequest("Page.setLifecycleEventsEnabled", godet.Params{
		"enabled": true,
	})
	if err != nil {
		log.Fatal(err)
	}

	enableDomainEvents(c)
}

func (cc *ChromeClient) targetCreated(p Message) {
	if p.Message("targetInfo") == nil || p.Message("targetInfo").String("type") != "page" {
		return
	}

	tid := p.Message("targetInfo").String("targetId")
	if _, ok := cc.targets[tid]; !ok {
		cc.targets[tid] = NewTarget(cc, tid, p.Message("targetInfo").String("url"))
	}
}

func (cc *ChromeClient) setupRootConn() {
	cc.Lock()
	defer cc.Unlock()

	for _, t := range cc.targets {
		t.Close()
	}

	var err error
	if cc.rootConn != nil {
		cc.rootConn.Close()
	}

	for {
		cc.rootConn, err = godet.Connect(fmt.Sprintf("localhost:%v", remoteDebuggingPort), verbose)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	cbm := map[string]func(Message){
		"Target.targetCreated": cc.targetCreated,
		"Inspector.detached":   func(p Message) { cc.setupRootConn() },
	}

	for method, cb := range cbm {
		cc.setCallback(cc.rootConn, method, cb)
	}

	cc.initConn(cc.rootConn)
}

func (cc *ChromeClient) setCallback(conn *godet.RemoteDebugger, method string, cb func(Message)) {
	conn.CallbackEvent(method, func(p godet.Params) {
		defer cc.Recover()
		cb(Message(p))
	})
}

func (cc *ChromeClient) OpenURL(url string) error {
	cc.Lock()
	defer cc.Unlock()
	log.Println("Opening URL:", url)

	r, err := cc.rootConn.SendRequest("Target.createTarget", godet.Params{
		"url": url,
	})
	if err != nil {
		return err
	}
	cc.watchedTargets = append(cc.watchedTargets, Message(r).String("targetId"))

	return nil
}

func (cc *ChromeClient) pageLifecycleEvent(p Message) {

	tid := p.String("frameId")
	if p.String("name") == "load" {
		for _, wt := range cc.watchedTargets {
			if wt == tid {
				t := cc.targets[tid]
				cc.LogEvent(&PageLifecycleEvent{
					Timestamp: time.Unix(int64(p.Int("timestamp")), 0),
					EventType: "PageLifecycleEvent",
					PolicyId:  t.Policy.Id,
					TargetId:  t.TargetId,

					FrameId:     p.String("frameId"),
					LoaderId:    p.String("loaderId"),
					Name:        p.String("name"),
					PolicyState: t.Policy.State(),
				})
				cc.pageLoaded(tid)
				cc.Shutdown(nil)
				return
			}
		}
	}
}
func (cc *ChromeClient) pageLoaded(tid string) {
	log.Println("Page loaded:", tid)

	// Pause briefly to allow everything to render.
	time.Sleep(5 * time.Second)

	log.Println("Taking screenshot:", tid)
	target := cc.targets[tid]

	r, err := target.SendRequest("Page.captureScreenshot", godet.Params{})
	if err != nil {
		log.Fatal("Error capturing screenshot:", err)
	}
	data, err := base64.StdEncoding.DecodeString(Message(r).String("data"))
	if err != nil {
		log.Fatal("Error decoding screenshot data:", err)
	}
	err = ioutil.WriteFile(path.Join(cc.runDir, "screenshot.png"), data, 0644)
	if err != nil {
		log.Fatal("Error writing screenshot to file:", err)
	}
}

func pipeToLog(rd io.Reader) {
	r := bufio.NewReader(rd)

lineLoop:
	for {
		s, err := r.ReadString('\n')
		if err != nil {
			break
		}

		// Filter out some noise.
		silence := []string{
			"Class RTCDispatcher is implemented in both",
			"Couldn't set selectedTextBackgroundColor from default",
			"Failed to call method: org.freedesktop",
			"DaemonVersion: GetAndBlock: failed",
		}
		for _, m := range silence {
			if strings.Contains(s, m) || s == "\n" {
				continue lineLoop
			}
		}

		log.Print(s)
	}
}
