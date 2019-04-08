package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

var chromiumPath string
var webServerPort int
var remoteDebuggingPort int
var chromiumLog bool
var verbose bool
var headless bool
var policyType int
var openDevTools bool
var openURL string
var runDir string
var uploadResults bool
var s3Bucket string

func init() {
	flag.StringVar(&chromiumPath, "chromium", defaultChromiumPath(), "path to Chromium binary")
	flag.IntVar(&webServerPort, "web-server-port", 8888, "web server port")
	flag.IntVar(&remoteDebuggingPort, "remote-debugging-port", 9222, "web server port")
	flag.BoolVar(&chromiumLog, "chromium-log", false, "log Chromium stdout/stderr")
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.BoolVar(&headless, "headless", false, "run headless Chromium")
	flag.IntVar(&policyType, "policy", policyTypeTrusting, "run headless Chromium")
	flag.BoolVar(&openDevTools, "open-devtools", false, "auto-open dev tools for new tabs")
	flag.StringVar(&openURL, "open-url", "", "URL to open")
	flag.StringVar(&runDir, "run-dir", "run", "directory to output run data")
	flag.BoolVar(&uploadResults, "upload-results", false, "upload results to S3")
	flag.StringVar(&s3Bucket, "s3-bucket", "eal5ub-exfiltration-study", "S3 bucket to download chromium from & upload results to")
	flag.Parse()

	if policyType >= policyTypeInvalid {
		log.Fatalf("bad policy flag: expected integer [0, %v]", policyTypeInvalid-1)
	}
}

func downloadChromium(awsSess *session.Session) {
	tarFileName := fmt.Sprintf("chromium/%v.tar.gz", runtime.GOOS)

	if _, err := os.Stat(path.Join("chromium", runtime.GOOS)); os.IsNotExist(err) {
		if _, err := os.Stat(tarFileName); os.IsNotExist(err) {
			log.Println("Downloading chromium...")
			file, err := os.Create(tarFileName)
			if err != nil {
				log.Fatal(err)
			}

			downloader := s3manager.NewDownloader(awsSess)
			_, err = downloader.Download(file, &s3.GetObjectInput{
				Bucket: aws.String(s3Bucket),
				Key:    aws.String(fmt.Sprintf("%v.tar.gz", runtime.GOOS)),
			})
			if err != nil {
				log.Fatal(err)
			}
		}

		log.Println("Expanding chromium...")
		cmd := exec.Command("tar", "-xzf", tarFileName, "-C", "chromium/")
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}

		if err := os.Remove(tarFileName); err != nil {
			log.Fatal(err)
		}
	}
}

func uploadResultsToS3(awsSess *session.Session, runDir string, namespace string) {
	tarFileName := fmt.Sprintf("%v.tar.gz", namespace)

	log.Println("Compressing run dir...")
	cmd := exec.Command("tar", "-czf", tarFileName, runDir)
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}

	f, err := os.Open(tarFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	log.Println("Uploading run dir...")
	uploader := s3manager.NewUploader(awsSess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(path.Join(runDir, tarFileName)),
		Body:   f,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(tarFileName); err != nil {
		log.Fatal(err)
	}
}

func defaultChromiumPath() string {
	if runtime.GOOS == "darwin" {
		return "chromium/darwin/Chromium.app/Contents/MacOS/Chromium"
	} else if runtime.GOOS == "linux" {
		return "chromium/linux/chrome"
	}
	log.Fatal("Running on unsupported OS")
	return ""
}

func main() {
	log.SetPrefix("> ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	namespace := "default"
	if openURL != "" {
		h := md5.New()
		io.WriteString(h, openURL)
		namespace = hex.EncodeToString(h.Sum(nil))
	}
	log.Println("Using namespace:", namespace)
	log.Println("URL:", openURL)
	rd := path.Join(runDir, namespace)

	os.MkdirAll(path.Join(rd, "logs"), os.ModePerm)

	f, err := os.OpenFile(path.Join(rd, "logs/stdout.log"), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	logOut := io.MultiWriter(os.Stdout, f)
	log.SetOutput(logOut)

	awsSess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:  aws.Config{Region: aws.String("us-east-1")},
		Profile: "exfiltration-study",
	}))
	downloadChromium(awsSess)

	cc := NewChromeClient(rd, policyType)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		cc.Shutdown(fmt.Errorf("SIGINT"))
		if err := cc.WaitStopped(); err != nil {
			log.Println("Stopped with error:", err)
		}
		os.Exit(1)
	}()

	cc.WaitReady()

	if openURL != "" {
		cc.OpenURL(openURL)
	}

	if err := cc.WaitStopped(); err != nil {
		log.Println("Stopped with error:", err)
		os.Exit(1)
	}

	cc.WriteLogToFile()

	if uploadResults {
		uploadResultsToS3(awsSess, rd, namespace)
	}
	log.Println("Run complete")
}
