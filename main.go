package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	already_done []string
	payload      string
	appendMode   bool
	rawMode      bool
	client       *http.Client
	wg           sync.WaitGroup
)

func init() {
	flag.StringVar(&payload, "p", "BAGOZAXSSOR>", "Payload to inject")
	flag.BoolVar(&appendMode, "a", false, "Append the payload instead of replacing value")
	flag.BoolVar(&rawMode, "raw", false, "Send payload raw without URL encoding")
}

func DoesSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func make_url(URI string) string {
	used_url := URI
	empty_url := URI

	if strings.Contains(used_url, "?") && strings.Contains(used_url, "=") {
		url_split := strings.Split(URI, "?")
		params := strings.Split(url_split[1], "&")

		for _, full_param := range params {
			if strings.Contains(full_param, "=") {
				splitted_param := strings.SplitN(full_param, "=", 2)
				key, val := splitted_param[0], splitted_param[1]

				if appendMode {
					// append payload
					used_url = strings.ReplaceAll(used_url, key+"="+val, key+"="+val+payload)
				} else {
					// replace payload
					used_url = strings.ReplaceAll(used_url, key+"="+val, key+"="+payload)
				}

				empty_url = strings.ReplaceAll(empty_url, key+"="+val, "")
			}
		}

		if !DoesSliceContains(already_done, empty_url) {
			already_done = append(already_done, empty_url)
		}

	} else {
		used_url = "NotValidURL"
	}
	return used_url
}

func req(URI string, f *os.File) {
	defer wg.Done()

	var targetURL string
	if rawMode {
		targetURL = URI
	} else {
		// encode payload part only
		encodedPayload := url.QueryEscape(payload)
		targetURL = strings.ReplaceAll(URI, payload, encodedPayload)
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "GxssScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	if rawMode {
		if strings.Contains(bodyStr, payload) && resp.StatusCode == 200 {
			fmt.Printf("[ $ ] :: XSS Vuln (payload: %s) :- %v\n", payload, URI)
			f.WriteString("[ $ ] XSS :: " + URI + "\n")
		} else if strings.Contains(bodyStr, strings.TrimRight(payload, ">")) && resp.StatusCode == 200 {
			fmt.Printf("[ * ] :: Reflection (payload: %s) :- %v\n", payload, URI)
			f.WriteString("[ * ] Reflection :: " + URI + "\n")
		} else {
			fmt.Printf("[ X ] :: Nothing :- %v\n", URI)
		}
	} else {
		encodedPayload := url.QueryEscape(payload)
		if (strings.Contains(bodyStr, payload) || strings.Contains(bodyStr, encodedPayload)) && resp.StatusCode == 200 {
			fmt.Printf("[ $ ] :: XSS Vuln (payload: %s) :- %v\n", payload, URI)
			f.WriteString("[ $ ] XSS :: " + URI + "\n")
		} else if (strings.Contains(bodyStr, strings.TrimRight(payload, ">")) ||
			strings.Contains(bodyStr, strings.TrimRight(encodedPayload, "%3E"))) && resp.StatusCode == 200 {
			fmt.Printf("[ * ] :: Reflection (payload: %s) :- %v\n", payload, URI)
			f.WriteString("[ * ] Reflection :: " + URI + "\n")
		} else {
			fmt.Printf("[ X ] :: Nothing :- %v\n", URI)
		}
	}
}

func main() {
	flag.Parse()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr, Timeout: 15 * time.Second}

	if flag.NArg() < 1 {
		fmt.Println("Usage: gxss [-a] [-p payload] [--raw] urls.txt")
		os.Exit(1)
	}

	urlsFile := flag.Arg(0)
	file, err := os.Open(urlsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	outFile, err := os.OpenFile("xssor_rzlts.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		u := make_url(line)
		if u != "NotValidURL" {
			wg.Add(1)
			go req(u, outFile)
		}
	}
	wg.Wait()
}
