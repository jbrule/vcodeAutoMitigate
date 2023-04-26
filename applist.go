package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/brian1917/vcodeapi"
)

func getApps(credsFile string, allApps bool, appList string, txtfile string) map[string]string {
	var apps = make(map[string]string)

	if allApps == true {
		appList, err := vcodeapi.ParseAppList(credsFile)
		if err != nil {
			log.Fatal(err)
		}
		for _, app := range appList {
			apps[app.AppID] = app.AppName
		}
	} else if appList != "" {
		for _, appID := range strings.Split(appList, ",") {
			apps[appID] = ""
		}
	} else {
		file, err := os.Open(txtfile)
		if err != nil {
			fmt.Println("error")
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			apps[scanner.Text()] = ""
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	return apps
}
