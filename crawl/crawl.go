package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

const numDomains = 500
const (
	seleniumPath     = "selenium-server-standalone-3.141.59.jar"
	chromeDriverPath = "chromedriver"
	port             = 8765
)

type crawlItem struct {
	domain string
	url    string
	depth  int
}

func main() {
	domains := domainList()

	q := []crawlItem{}
	for _, domain := range domains {
		q = append(q, crawlItem{
			domain: domain,
			url:    fmt.Sprintf("https://%v/", domain),
			depth:  0,
		})
	}

	f, err := os.Create("urls.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	domainURLS := sampleURLs(crawl(q), 5)

	for domain, urls := range domainURLS {
		for _, url := range urls {
			f.WriteString(fmt.Sprintf("%v %v\n", domain, url))
		}
	}
}

func domainList() []string {
	bf, err := os.Open("blacklist.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer bf.Close()

	blacklist := make(map[string]struct{})

	scanner := bufio.NewScanner(bf)
	for scanner.Scan() {
		blacklist[scanner.Text()] = struct{}{}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	f, err := os.Open("tranco_2549.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	domains := []string{}

	for {
		line, err := reader.Read()
		if err != nil {
			break
		}

		domain := line[1]

		if _, ok := blacklist[domain]; ok {
			continue
		}

		if len(domains) < numDomains {
			domains = append(domains, domain)
		} else {
			break
		}
	}

	return domains
}

func sampleURLs(domainURLs map[string][]string, n int) map[string][]string {
	ret := make(map[string][]string)

	for domain, urls := range domainURLs {
		urlMap := make(map[string]struct{})
		for _, url := range urls {
			urlMap[url] = struct{}{}
		}

		uniqueURLS := []string{}
		for url, _ := range urlMap {
			uniqueURLS = append(uniqueURLS, url)
		}

		urlsSample := []string{}
		for i, j := range rand.Perm(len(uniqueURLS)) {
			if i >= n {
				break
			}

			urlsSample = append(urlsSample, uniqueURLS[j])
		}
		ret[domain] = urlsSample
	}

	return ret
}

func crawl(q []crawlItem) map[string][]string {
	opts := []selenium.ServiceOption{
		selenium.ChromeDriver(chromeDriverPath),
		selenium.Output(os.Stderr),
	}

	service, err := selenium.NewSeleniumService(seleniumPath, port, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer service.Stop()

	caps := selenium.Capabilities{"browserName": "chrome"}
	caps.AddChrome(chrome.Capabilities{
		Args: []string{"--headless"},
		Prefs: map[string]interface{}{
			"profile.default_content_setting_values.notifications":  2,
			"profile.managed_default_content_settings.cookies":      2,
			"profile.managed_default_content_settings.plugins":      1,
			"profile.managed_default_content_settings.geolocation":  2,
			"profile.managed_default_content_settings.media_stream": 2,
			"profile.managed_default_content_settings.images":       2,
			"profile.managed_default_content_settings.stylesheets":  2,
			"profile.managed_default_content_settings.popups":       2,
		},
	})

	domainURLs := make(map[string][]string)
	domainCrawlLimit := 100

	for len(q) > 0 {
		c := q[0]
		q = q[1:]

		if len(domainURLs[c.domain]) == 0 {
			domainURLs[c.domain] = []string{c.url}
		}

		if len(domainURLs[c.domain]) >= domainCrawlLimit {
			continue
		}

		if c.depth > 2 {
			continue
		}

		wd, err := selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d/wd/hub", port))
		if err != nil {
			log.Fatal(err)
		}

		wd.SetPageLoadTimeout(15 * time.Second)

		p := 0
		for _, urls := range domainURLs {
			p += len(urls)
		}
		log.Printf("Progress: %v/%v", p, domainCrawlLimit*numDomains)

		log.Println("Fetching:", c.depth, c.url)
		if err := wd.Get(c.url); err != nil {
			log.Print(err)
			log.Printf("Fetch error: %v %v %v", c.domain, c.depth, c.url)
			continue
		}

		links, err := wd.FindElements(selenium.ByCSSSelector, "a[href]")
		if err != nil {
			log.Print(err)
			continue
		}

	linkLoop:
		for _, link := range links {
			url, err := link.GetAttribute("href")
			if err != nil {
				log.Print(err)
				continue
			}

			pattern := fmt.Sprintf("^https?://([a-z0-9\\.]+\\.)?%v/", c.domain)
			matched, err := regexp.MatchString(pattern, url)
			if err != nil {
				log.Fatal(err)
			}
			if !matched {
				continue
			}

			for _, url2 := range domainURLs[c.domain] {
				if url == url2 {
					continue linkLoop
				}
			}

			log.Println("Found:", url)
			domainURLs[c.domain] = append(domainURLs[c.domain], url)

			if len(domainURLs[c.domain]) >= domainCrawlLimit {
				break
			}

			q = append(q, crawlItem{
				domain: c.domain,
				url:    url,
				depth:  c.depth + 1,
			})
		}

		wd.Quit()
	}

	return domainURLs
}
