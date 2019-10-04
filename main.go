package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gourmetproject/dnsanalyzer/dnsresult"
	"github.com/gourmetproject/gourmet"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Config struct {
	Threshold int
	Token     string `yaml:"bedtime_bot_token"`
	User      string `yaml:"my_user_id"`
}

var (
	config *Config
	counter int
	threshold = 10
	notified bool
	initFail bool
)

func init() {
	var c interface{}
	var ok bool
	var err error
	c, err = gourmet.GetAnalyzerConfig("github.com/gourmetproject/bedtimeanalyzer")
	if err != nil {
		initFail = true
		log.Fatal(err)
	}
	config, ok = c.(*Config)
	if !ok {
		initFail = true
		log.Fatal(errors.New("failed to cast results of GetAnalyzerConfig to bedtimeanalyzer.Config"))
	}
}

type bedtimeAnalyzer struct{}

func NewAnalyzer() gourmet.Analyzer {
	return &bedtimeAnalyzer{}
}

// lateNightNetflixAnalyzer filters on DNS packets that have:
//   1. Already been analyzed by the Gourmet DNS analyzer
//   2. Occur after 9pm
//   3. We haven't sent a Slack notification yet today
func (bta *bedtimeAnalyzer) Filter(c *gourmet.Connection) bool {
	if notified || initFail {
		return false
	}
	_, ok := c.Analyzers["dns"]; if ok {
		// time.Clock() returns the hour, minute, and second for a timestamp
		hour, _, _ := c.Timestamp.Clock()
		if hour > 21 {
			return true
		}
	}
	return false
}

func (bta *bedtimeAnalyzer) Analyze(c *gourmet.Connection) (gourmet.Result, error) {
	dnsResult, ok := c.Analyzers["dns"].(dnsresult.DNS); if !ok {
		log.Println("DNS Analyzer Result invalid")
	}
	for _, answer := range dnsResult.Answers {
		if strings.Contains(answer.Name, "netflix.com") {
			counter++
			if counter >= threshold {
				hr, min, _ := c.Timestamp.Clock()
				msg := fmt.Sprintf("%s is watching Netflix at %d:%d!", c.DestinationIP, hr, min)
				err := sendSlackNotification(config.Token, config.User, msg)
				if err != nil {
					log.Println(err)
				} else {
					notified = true
				}
				counter = 0
			}
		}
	}
	return nil, nil
}

type Message struct {
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
		Channel: channel,
		Text: message,
	}
	marshaledMessage, err := json.Marshal(messageBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(marshaledMessage))
	header := http.Header{}
	header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	header.Add("Content-type", "application/json")
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

