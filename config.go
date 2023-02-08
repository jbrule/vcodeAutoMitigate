package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"strings"
)

type config struct {
	Name string `json:name`

	Auth struct {
		CredsFile string `json:"credsFile"`
	} `json:"auth"`

	Scope struct {
		AllApps         bool   `json:"allApps"`
		AppList         string `json:"appList"`
		AppListTextFile string `json:"appListTextFile"`
		RegexAppNameExclude         string   `json:"regexAppNameExclude"`
	} `json:"scope"`

	Mode struct {
		LogOnly          bool `json:"logOnly"`
		ProposeOnly      bool `json:"proposeOnly"`
		ProposeAndAccept bool `json:"proposeAndAccept"`
	} `json:"mode"`

	TargetFlaws struct {
		CWEList           string `json:"cweList"`
		RequireTextInDesc bool   `json:"requireTextInDesc"`
		RequiredText      []string `json:"requiredText"`
		Static            bool   `json:"static"`
		Dynamic           bool   `json:"dynamic"`
	} `json:"targetFlaws"`

	MitigationInfo struct {
		MitigationType  string `json:"mitigationType"`
		ProposalComment string `json:"proposalComment"`
		ApprovalComment string `json:"approvalComment"`
	} `json:"mitigationInfo"`
}

var configFile string
var mode string

func init() {
	flag.StringVar(&configFile, "config", "", "Config Filename")
	flag.StringVar(&mode,"mode","config","[LogOnly|ProposeOnly|ProposeAndAccept]")
}

func resetMode(config *config,newMode string) {
	config.Mode.LogOnly = false
	config.Mode.ProposeOnly = false
	config.Mode.ProposeAndAccept = false

	switch newMode {
		case "LogOnly":
			config.Mode.LogOnly = true
		case "ProposeOnly":
			config.Mode.ProposeOnly = true
		case "ProposeAndAccept":
			config.Mode.ProposeAndAccept = true
		default:
	}
}

func parseConfig() config {

	flag.Parse()

	//READ CONFIG FILE
	var config config

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}

  //Handle Mode Switch (if provided)
	if mode != "config" {
		resetMode(&config, mode)
	}

	// CHECK FOR MODE ERRORS
	modeCounter := 0
	if config.Mode.LogOnly == true {
		modeCounter++
	}
	if config.Mode.ProposeOnly == true {
		modeCounter++
	}
	if config.Mode.ProposeAndAccept == true {
		modeCounter++
	}
	if modeCounter > 1 {
		log.Fatal("[!]Only one mode is allowed to be set to true")
	}
	if modeCounter == 0 {
		log.Fatal("[!]At least one mode has to be set to true.")
	}

	// REMOVE SPACES FROM CWE LIST
	if strings.Contains(config.TargetFlaws.CWEList, " ") {
		config.TargetFlaws.CWEList = strings.Replace(config.TargetFlaws.CWEList, " ", "", -1)
	}

	// REMOVE SPACES FROM APP LIST
	if strings.Contains(config.Scope.AppList, " ") {
		config.Scope.AppList = strings.Replace(config.Scope.AppList, " ", "", -1)
	}

	// IF REQUIRED TEXT IS TRUE, CONFIRM TEXT PRESENT
	if config.TargetFlaws.RequireTextInDesc == true && len(config.TargetFlaws.RequiredText) == 0 {
		log.Fatal("[!]Need to provide the text to search for in description")
	}

	// CHECK MITIGATION TYPE IS VALID
	if config.MitigationInfo.MitigationType != "appdesign" &&
		config.MitigationInfo.MitigationType != "osenv" &&
		config.MitigationInfo.MitigationType != "netenv" &&
		config.MitigationInfo.MitigationType != "fp" {
		log.Fatal("[!]Mitigation type needs to be appdesign, osenv, netenv, or fp")
	}

	return config
}
