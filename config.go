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
		CredsFile         string `json:"credsFile"`
		ProposerCredsFile string `json:"proposerCredsFile"`
		AcceptorCredsFile string `json:"acceptorCredsFile"`
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
		SeverityList      string `json:"severityList"`
		CWEList           string `json:"cweList"`
		RequireTextInDesc bool   `json:"requireTextInDesc"`
		RequiredText      []string `json:"requiredText"`
		Module            string `json:"module"`
		Source            string `json:"source"`
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

	if config.Name == "" {
		config.Name = "vcodeAutoMitigate"
	}

	// Creds file management

	// Check if credsFile or proposer+acceptor are provided. Cannot provide both
	if (len(config.Auth.ProposerCredsFile) > 0 || len(config.Auth.AcceptorCredsFile) > 0) && len(config.Auth.CredsFile) > 0 {
		log.Fatal("[!]Credentials must be supplied for either credsFile or proposerCredsFile+acceptorCredsFile. Cannot supply both.")
	} else if 
	  (len(config.Auth.ProposerCredsFile) > 0 && len(config.Auth.AcceptorCredsFile) == 0) ||
		(len(config.Auth.ProposerCredsFile) == 0 && len(config.Auth.AcceptorCredsFile) > 0) && 
		len(config.Auth.CredsFile) == 0 {
		log.Fatal("[!]Both proposerCredsFile and acceptorCredsFile must be provided")
	}

	// Set proposerCredFile and acceptorCredFile to credFile if omitted and credFile is provided
	if len(config.Auth.ProposerCredsFile) == 0 && len(config.Auth.AcceptorCredsFile) == 0 && len(config.Auth.CredsFile) > 0 {
		config.Auth.ProposerCredsFile = config.Auth.CredsFile
		config.Auth.AcceptorCredsFile = config.Auth.CredsFile
	}

	// REMOVE SPACES FROM Severity LIST
	if strings.Contains(config.TargetFlaws.SeverityList, " ") {
		config.TargetFlaws.SeverityList = strings.Replace(config.TargetFlaws.SeverityList, " ", "", -1)
	}

		// REMOVE SPACES FROM Severity LIST
		if len(config.TargetFlaws.SeverityList) == 0 {
			config.TargetFlaws.SeverityList = "*"
		}

	// REMOVE SPACES FROM CWE LIST
	if strings.Contains(config.TargetFlaws.CWEList, " ") {
		config.TargetFlaws.CWEList = strings.Replace(config.TargetFlaws.CWEList, " ", "", -1)
	}

	// REMOVE SPACES FROM APP LIST
	if strings.Contains(config.Scope.AppList, " ") {
		config.Scope.AppList = strings.Replace(config.Scope.AppList, " ", "", -1)
	}

	// REMOVE SPACES FROM APP LIST
	if config.Scope.AllApps == true && len(config.Scope.AppList) > 0 {
		log.Fatal("[!]AllApps and AppList are mutually exclusive settings. Either set AppApps false or remove apps from AppList")
	}

	// IF REQUIRED TEXT IS TRUE, CONFIRM TEXT PRESENT
	if config.TargetFlaws.RequireTextInDesc == true && len(config.TargetFlaws.RequiredText) == 0 {
		log.Fatal("[!]Need to provide the text to search for in description")
	}

	// IF MODULE IS PROVIDED DYNAMIC SCAN CANNOT BE TRUE
	if config.TargetFlaws.Dynamic == true && (len(config.TargetFlaws.Module) != 0 || len(config.TargetFlaws.Source) != 0) {
		log.Fatal("[!]Dynamic and module,source parameters are mutually exclusive.")
	}

	// DISALLOW WILDCARD MITIGATION ACROSS ALLAPPS
	if config.TargetFlaws.CWEList == "*" && config.Scope.AllApps == true {
		log.Fatal("[!]Wildcard CweList cannot be used with AllApps option.")
	}

	// CHECK MITIGATION TYPE IS VALID
	if config.MitigationInfo.MitigationType != "appdesign" &&
		config.MitigationInfo.MitigationType != "osenv" &&
		config.MitigationInfo.MitigationType != "netenv" &&
		config.MitigationInfo.MitigationType != "acceptrisk" &&
		config.MitigationInfo.MitigationType != "fp" {
		log.Fatal("[!]Mitigation type needs to be appdesign, osenv, netenv, acceptrisk, or fp")
	}

	return config
}
