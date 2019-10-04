package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/gourmetproject/dnsanalyzer/dnsresult"
	"github.com/gourmetproject/gourmet"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Config struct {
	Threshold int
	Token     string `json:"bedtime_bot_token"`
	User      string `json:"my_user_id"`
}

var (
	config Config
	counter int
	threshold = 10
	notified bool
	initFail bool
)

func init() {
	configBytes, err := gourmet.GetAnalyzerConfig("github.com/gourmetproject/bedtimeanalyzer")
	if err != nil {
		initFail = true
		log.Fatal(err)
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		initFail = true
		log.Fatal(err)
	}
}

type bedtimeResult struct{}

func (br *bedtimeResult) Key() string {
	return "netflix_detector"
}

type bedtimeAnalyzer struct{}

func NewAnalyzer() gourmet.Analyzer {
	return &bedtimeAnalyzer{}
}

// lateNightNetflixAnalyzer filters on DNS packets that have:
//   1. Already been analyzed by the Gourmet DNS analyzer
//   2. Occur after 9pm and before 6am
//   3. We haven't sent a Slack notification yet
func (bta *bedtimeAnalyzer) Filter(c *gourmet.Connection) bool {
	if notified || initFail {
		return false
	}
	_, ok := c.Analyzers["dns"]; if ok {
		// time.Clock() returns the hour, minute, and second for a timestamp
		hour, _, _ := c.Timestamp.Clock()
		if hour > 21 || hour < 6 {
			return true
		}
	}
	return false
}

func (bta *bedtimeAnalyzer) Analyze(c *gourmet.Connection) (gourmet.Result, error) {
	dnsResult, ok := c.Analyzers["dns"].(*dnsresult.DNS); if !ok {
		log.Println("DNS Analyzer Result invalid")
	}
	if len(dnsResult.Answers) > 0 {
		for _, answer := range dnsResult.Answers {
			if strings.Contains(answer.Name, "netflix") {
				msg := fmt.Sprintf("%s is watching Netflix at %s!", c.DestinationIP, c.Timestamp.Format("3:04PM"))
				err := sendSlackNotification(config.Token, config.User, msg)
				if err != nil {
					log.Println(err)
				} else {
					notified = true
					break
				}
			}
		}
	}
	return &bedtimeResult{}, nil
}

type Message struct {
	Token   string `json:"token"`
	Channel string `json:"channel"`
	Text    string `json:"text"`
}

type MessageResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func sendSlackNotification(token, channel, message string) (err error) {
	var mr MessageResponse
	messageBody := &Message {
		Token: token,
		Channel: channel,
		Text: message,
	}
	marshaledMessage, err := json.Marshal(messageBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(marshaledMessage))
	if err != nil {
		return err
	}
	header := http.Header{}
	header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	header.Add("Content-Type", "application/json")
	req.Header = header
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bodyContents, &mr)
	if err != nil {
		return err
	}
	if !mr.Ok {
		return errors.New(fmt.Sprintf("Slack error: %s", mr.Error))
	}
	return nil
}

