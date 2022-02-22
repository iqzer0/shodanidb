package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
)

type Response struct {
	CPES	[]string
	Hostnames	[]string
	IP	string
	Ports	[]int32
	Tags	[]string
	Vulns	[]string
}

func main() {

	var noCPEs bool
	flag.BoolVar(&noCPEs, "nc", false, "Hide CPEs")

	var noHostnames bool
	flag.BoolVar(&noHostnames, "nh", false, "Hide hostnames")

	var noTags bool
	flag.BoolVar(&noTags, "nt", false, "Hide tags")

	var noVulns bool
	flag.BoolVar(&noVulns, "nv", false, "Hide vulnerabilities")

	var noColor bool
	flag.BoolVar(&noColor, "nocolor", false, "Disable color in output")

	var jsonFile string
	flag.StringVar(&jsonFile, "json", "", "Save output to JSON format")

	flag.Parse()


	var ips []string

	if flag.NArg() > 0 {
		ips = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			ips = append(ips, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	channel := make(chan Response)
	var wg sync.WaitGroup

	for i := 0; i < len(ips); i++ {
		wg.Add(1)

		i := i

		go func() {
			defer wg.Done()
			jsonData := getData(ips[i])
			channel <- jsonData
		}()

	}

	go func() {
		wg.Wait()
		close(channel)
	}()

	if jsonFile != "" {
		saveJson(channel, jsonFile)
		return
	}

	for i := 0; i < len(ips); i++ {
		printResult(<-channel, noCPEs, noHostnames, noTags, noVulns, noColor)
	}
}


func getData(ip string) Response {

	res, err := http.Get(
		fmt.Sprintf("https://internetdb.shodan.io/%s", ip),
	)

	if err != nil {
		log.Fatalf("Couldn't connect to the server!")
		return Response{}
	}

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Couldn't read the data!")
		return Response{}
	}

	res.Body.Close()

	var jsonData Response
	err = json.Unmarshal(raw, &jsonData)

	if err != nil {
		log.Fatalf("The data is incorrect!")
		return Response{}
	}

	return jsonData
}


func saveJson(chData chan Response, jsonFile string) {

	var jsonDatas []Response
	for jsonData := range chData {
		if jsonData.IP != "" {
			jsonDatas = append(jsonDatas, jsonData)
		}
	}

	if len(jsonDatas) != 0 {
		stringData, _ := json.Marshal(jsonDatas)
		_ = ioutil.WriteFile(jsonFile, stringData, 0644)
	}
}


func printResult(jsonData Response, noCPEs bool, noHostnames bool, noTags bool, noVulns bool, noColor bool) {

	builder := &strings.Builder{}

	if jsonData.IP == "" {
		return
	}

	fmt.Println(jsonData.IP)

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(jsonData.Ports)), ", "), "[]")

	if !noColor {
		builder.WriteString("Ports: " + aurora.Green(ports).String() + "\n")
	} else {
		builder.WriteString("Ports: " + ports + "\n")
	}

	if (!noCPEs && len(jsonData.CPES) > 0) {
		cpes := strings.Join(jsonData.CPES, ", ")
		if !noColor {
			builder.WriteString("CPEs: " + aurora.Yellow(cpes).String() + "\n")
		} else {
			builder.WriteString("CPEs: " + cpes + "\n")
		}
	}

	if (!noVulns && len(jsonData.Vulns) > 0) {
		vulns := strings.Join(jsonData.Vulns, ", ")
		if !noColor {
			builder.WriteString("Vulnerabilities: " + aurora.Red(vulns).String() + "\n")
		} else {
			builder.WriteString("Vulnerabilities: " + vulns + "\n")
		}
	}

	if (!noHostnames && len(jsonData.Hostnames) > 0) {
		hostnames := strings.Join(jsonData.Hostnames, ", ")
		if !noColor {
			builder.WriteString("Hostnames: " + aurora.Blue(hostnames).String() + "\n")
		} else {
			builder.WriteString("Hostnames: " + hostnames + "\n")
		}
	}

	if (!noTags && len(jsonData.Tags) > 0) {
		tags := strings.Join(jsonData.Tags, ", ")
		if !noColor {
			builder.WriteString("Tags: " + aurora.Magenta(tags).String() + "\n")
		} else {
			builder.WriteString("Tags: " + tags + "\n")
		}
	}

	fmt.Println(builder.String())
}