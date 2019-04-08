package main

import (
	"log"
	"net/http"
	"text/template"
)

type TestHandler struct {
	Path                  string
	RemoteScripts         []string
	InlineScripts         []string
	HTMLBody              string
	ExpectTaintingAPIName string
	ExpectPolicyViolated  bool
	ExpectReqResourceType string
}

func (h TestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// NOTE: We use text/template to avoid sanitization.
	tmpl := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<link rel="icon" href="data:,">
		<title>{{.Path}}</title>
		{{range .RemoteScripts}}
			<script src="{{.}}"></script>
		{{end}}
		{{range .InlineScripts}}
			<script>{{.}}</script>
		{{end}}
	</head>
	<body>
		{{.HTMLBody}}
	</body>
	</html>
	`

	t := template.Must(template.New(h.Path).Parse(tmpl))
	err := t.Execute(w, h)
	if err != nil {
		log.Fatal(err)
	}
}

var testHandlers = []TestHandler{
	TestHandler{
		Path: "/Policy1/TestXHR/Pass",
		InlineScripts: []string{
			`
				window.onload = function() {
					var r = new XMLHttpRequest();
					r.open("GET", "https://httpbin.org/get");
					r.send();
				}
			`,
		},
	},
	TestHandler{
		Path: "/Policy1/TestXHR/Fail",
		InlineScripts: []string{
			`
				window.onload = function() {
					console.log(document.cookie);
					var r = new XMLHttpRequest();
					r.open("GET", "https://httpbin.org/get");
					r.send();
				}
			`,
		},
	},
	TestHandler{
		Path: "/Policy1/TestIframeCreate/Fail",
		InlineScripts: []string{
			`
				window.onload = function() {
					var iframe = document.createElement("iframe");
					iframe.src = "https://httpbin.org/html";
					document.body.appendChild(iframe);
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestIframeNavigate/Fail",
		HTMLBody: `
			<iframe id="iframe" src="https://httpbin.org/html"></iframe>
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					var iframe = document.getElementById("iframe");
					iframe.src = "https://httpbin.org/html?foo=bar"
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestClickLink/Fail",
		HTMLBody: `
			<a id="link" href="https://httpbin.org/get?foo=bar">Click me</a>
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					document.getElementById("link").click();
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestPopup/Pass",
		InlineScripts: []string{
			`
				window.open("https://httpbin.org/html");
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestPopup/Fail",
		InlineScripts: []string{
			`
				console.log(document.cookie);
				window.open("https://httpbin.org/html");
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestCreateImage/Fail",
		InlineScripts: []string{
			`
				window.onload = function() {
					var img = document.createElement("img");
					img.src = "https://httpbin.org/image/png";
					document.body.appendChild(img);
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestUpdateImage/Fail",
		HTMLBody: `
			<img id="img" src="https://httpbin.org/image/png">
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					var img = document.getElementById("img");
					img.src = "https://httpbin.org/image/jpeg";
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestCreateScript/Pass",
		InlineScripts: []string{
			`
				window.onload = function() {
					var script = document.createElement("script");
					script.innerHTML = "console.log('the script ran')";
					document.body.appendChild(script);
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestCreateScriptXHR/Fail",
		InlineScripts: []string{
			`
				window.onload = function() {
					var script = document.createElement("script");
					script.innerHTML = " \
						console.log(document.cookie); \
						var r = new XMLHttpRequest(); \
						r.open('GET', 'https://httpbin.org/get'); \
						r.send(); \
					";
					document.body.appendChild(script);
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestSubmitForm/Fail",
		HTMLBody: `
			<form id="form" method="post" action="https://httpbin.org/post"></form>
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					var form = document.getElementById("form");
					form.submit();
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestClickSubmitForm/Fail",
		HTMLBody: `
			<form id="form" method="post" action="https://httpbin.org/post">
				<input id="submit" type="submit" value="Submit">
			</form>
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					var button = document.getElementById("submit");
					button.click();
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy1/TestEval/Fail",
		HTMLBody: `
			<form id="form" method="post" action="https://httpbin.org/post">
				<input id="submit" type="submit" value="Submit">
			</form>
		`,
		InlineScripts: []string{
			`
				window.onload = function() {
					eval("let x = document.cookie");
					var button = document.getElementById("submit");
					button.click();
				};
			`,
		},
	},

	TestHandler{
		Path: "/Policy2/TestSameHostname/Pass",
		RemoteScripts: []string{
			"/static/test_script_1.js",
			"https://localhost:8888/static/test_script_2.js",
			"https://localhost:8888/static/test_script_3.js",
		},
		InlineScripts: []string{
			`
				window.onload = function() {
					var r = new XMLHttpRequest();
					r.open("GET", "https://httpbin.org/get");
					r.send();
				}
			`,
		},
	},

	TestHandler{
		Path: "/Policy2/TestDifferentHostname/Pass",
		RemoteScripts: []string{
			"https://eal-exfiltration.s3.amazonaws.com/test_script_1.js",
			"https://localhost:8888/static/test_script_2.js",
			"https://localhost:8888/static/test_script_3.js",
		},
		InlineScripts: []string{
			`
				window.onload = function() {
					var r = new XMLHttpRequest();
					r.open("GET", "https://httpbin.org/get");
					r.send();
				}
			`,
		},
	},

	TestHandler{
		Path: "/Policy2/TestXHRDifferentHostname/Fail",
		RemoteScripts: []string{
			"/static/test_script_1.js",
			"https://localhost:8888/static/test_script_2.js",
			"https://eal-exfiltration.s3.amazonaws.com/test_script_3.js",
		},
	},

	TestHandler{
		Path: "/Policy2/TestSameHostnameCreateScriptXHR/Pass",
		RemoteScripts: []string{
			"/static/test_script_4.js",
		},
	},

	TestHandler{
		Path: "/Policy2/TestDifferentHostnameCreateScriptXHR/Fail",
		RemoteScripts: []string{
			"https://eal-exfiltration.s3.amazonaws.com/test_script_4.js",
		},
	},
}
