/*
Johann Van Niekerk hdysec@gmail.com
*/

package cmd

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

var greenPlus = fmt.Sprintf("[%s]", color.HiGreenString("++"))
var redMinus = fmt.Sprintf("[%s]", color.HiRedString("--"))
var yellowPlus = fmt.Sprintf("[%s]", color.HiYellowString("+-"))

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hdySSL",
	Short: "Automate some of the SSL/TLS scanning for end of engagements.",
	Long: `
A tool used for completing the SSL/TLS scanning through multiple available tools and then digesting the 
the content for findings. Docker is required to be installed to ensure that latest tools and their versions are utilised
and removes the need to install tools manually and updating them with dependencies.

Usage:
hdySSL -d <domain>
hdySSL -D <domainlist.txt>
`,

	Run: func(cmd *cobra.Command, args []string) {
		if !dependencyChecker() {
			fmt.Println("Dependencies not met due to one/all of the following:")
			fmt.Println("		- Ensure Docker and Git are installed")
			fmt.Println("		- Ensure Docker and Git are in $PATH")
			fmt.Println("		- Ensure internet connectivity is working and no issues with DNS or host files")
			return
		}

		err := ensureSslscanImageExists()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				fmt.Printf("%s Error ensuring sslscan image exists", redMinus)
				fmt.Printf("%s Standard Error: \n", redMinus, string(exitErr.Stderr))
			} else {
				fmt.Printf("%s Error with program: %s\n", redMinus, err)
			}
		}

		domainName, _ := cmd.Flags().GetString("domain")
		domainNameList, _ := cmd.Flags().GetString("domainList")
		domains := loadDomains(domainName, domainNameList)
		outputToStdout := len(domains) == 1

		// Concurrency when dealing with a list of domains and executing the scans across multiple domain names
		var wg sync.WaitGroup
		for _, domain := range domains {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				//processScan(d, outputFilename)
				processScan(d, outputToStdout)
			}(domain)
		}
		wg.Wait()
	},
}

func dependencyChecker() bool {
	//fmt.Println("Debug: Executing dependencyChecker()")

	// check system OS type before issuing ping command due to different (ping) flag requirements.
	var outboundCheck *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows ping command, sending 1 packet
		outboundCheck = exec.Command("ping", "google.com", "-n", "1")
	} else {
		// Linux and macOS ping command, sending 1 packet
		outboundCheck = exec.Command("ping", "google.com", "-c", "1")
	}

	_, err := outboundCheck.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The command executed, but ping failed; exitErr.ExitCode() will be non-zero
			fmt.Printf("%s Outbound Ping to google.com unsuccessful with exit code %d\n", redMinus, exitErr.ExitCode())
		} else {
			// The command did not execute successfully (e.g., command not found)
			fmt.Printf("%s Ping command failed to execute: %s\n", redMinus, err)
		}
		os.Exit(1)
	}
	fmt.Printf("%s Check Internet Connectivity\n", greenPlus)

	// Check for Docker installation via CLI
	dockerCheck := exec.Command("docker", "--version")
	if err := dockerCheck.Run(); err != nil {
		fmt.Printf("%s Docker check failed, it is either not installed, not running with elevated privileges, or the process is currently not running: %s\n", redMinus, err)
		os.Exit(1)
	}
	fmt.Printf("%s Check Docker Setup\n", greenPlus)

	// Check for Git installation via CLI - Required for Git Clone
	gitCheck := exec.Command("git", "--version")
	if err := gitCheck.Run(); err != nil {
		fmt.Printf("%s Git check failed, it is either not installed or there is an issue with your PATH: %s\n", redMinus, err)
		os.Exit(1)
	}
	fmt.Printf("%s Check Git Setup\n", greenPlus)

	return true
}

func ensureSslscanImageExists() error {
	//fmt.Println("Debug: Executing ensureSslscanImageExists()")

	checkImage := exec.Command("docker", "images", "-q", "sslscan:sslscan")
	output, err := checkImage.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Printf("%s Issues checking if existing image exists for SSLSCAN", redMinus)
			fmt.Printf("%s Standard Error: \n", redMinus, string(exitErr.Stderr))
		} else {
			fmt.Printf("%s Error with program: \n", redMinus, err)
		}
	}

	if strings.TrimSpace(string(output)) == "" {
		// Clone the sslscan repo if the image does not exist
		fmt.Printf("%s Docker image 'sslscan' is missing \n", redMinus)
		fmt.Printf("%s Cloning and building 'sslscan' \n", yellowPlus)

		sslscanClone := exec.Command("git", "clone", "https://github.com/rbsec/sslscan.git")
		if err := sslscanClone.Run(); err != nil {
			fmt.Printf("%s Problems with executing Git Clone, attempt manual installation to check for connectivity \n 	- git clone https://github.com/rbsec/sslscan.git", redMinus)
			os.Exit(1)
		}

		// Build the sslscan Docker image
		sslscanInstall := exec.Command("docker", "build", "-t", "sslscan:sslscan", "./sslscan/", "--network host")
		if err := sslscanInstall.Run(); err != nil {
			fmt.Printf("%s Problems with executing Docker Build on the ./sslscan/ directory, attempt manual installation to check for connectivity", redMinus)
			fmt.Println("docker build -t sslscan:sslscan ./sslscan/ --network host")
			os.Exit(1)
		}

		// remove the git clone folder as it is not required any more
		err = os.RemoveAll("./sslscan/")
		if err != nil {
			fmt.Printf("%s Failed to delete & remove the remnants from the git cloned files.\n Do it manually as the folder and it's contents are not needed. \n Error: %s", redMinus, err)
		}
		fmt.Printf("%s Setup for 'sslscan' complete \n", greenPlus)
	}
	return nil
}

func processScan(domain string, outputToStdout bool) {
	//fmt.Println("Debug: Executing processScan()")

	// Specify filenames to print
	testsslFile := fmt.Sprintf("testssl.%s.txt", domain)
	sslyzeFile := fmt.Sprintf("sslyze.%s.txt", domain)
	sslscanFile := fmt.Sprintf("sslscan.%s.txt", domain)

	fmt.Printf("%s Running testssl.sh \n", greenPlus)
	runCommand("docker", []string{"run", "--rm", "--network", "host", "drwetter/testssl.sh", domain}, testsslFile, outputToStdout)

	fmt.Printf("%s Running sslyze \n", greenPlus)
	runCommand("docker", []string{"run", "--rm", "--network", "host", "nablac0d3/sslyze:5.0.0", domain}, sslyzeFile, outputToStdout)

	fmt.Printf("%s Running sslscan \n", greenPlus)
	runCommand("docker", []string{"run", "--rm", "--network", "host", "sslscan:sslscan", domain}, sslscanFile, outputToStdout)
}

func runCommand(command string, args []string, outputFile string, outputToStdout bool) {
	//fmt.Println("Executing runCommand()")
	//fmt.Println("Running command:\n", command, strings.Join(args, " ")) // Display command
	fmt.Printf("%s Running command: %s %s\n", greenPlus, command, strings.Join(args, " ")) // Display command
	fmt.Println("\n")

	// Open the output file
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%s Error opening file: %s", redMinus, err)
		return
	}

	// Ensure file is closed once the runCommand() function has completed
	defer file.Close()

	// Set up the command
	cmd := exec.Command(command, args...)

	if outputToStdout {
		// Create a multi-writer to write to both stdout and the file
		multiWriter := io.MultiWriter(os.Stdout, file)
		cmd.Stdout = multiWriter
		cmd.Stderr = multiWriter
	} else {
		// Direct output only to the file
		cmd.Stdout = file
		cmd.Stderr = file
		fmt.Printf("%s Running scan across all domains, please wait. \n", greenPlus)
	}

	// Run the command
	err = cmd.Run()
	if err != nil {
		fmt.Printf("%s Error running the following command %s: %s\n", redMinus, command, err)
	}
}

func loadDomains(domainName, domainNameList string) []string {
	// Ensuring there is a valid domain name entry in CLI or in text file
	//fmt.Println("Debug: Executing loadDomains()")

	if domainName != "" {
		return []string{domainName}
	}
	if domainNameList != "" {
		return readLinesFromFile(domainNameList)
	}
	return []string{}
}

func readLinesFromFile(filePath string) []string {
	//read all URLs from textfile
	//fmt.Println("Debug: Executing readLinesFromFile()")

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("%s Error opening file to read all URLs %s: %s\n", redMinus, filePath, err)
		os.Exit(1)
	}

	// Ensure file is closed once the readLinesFromFile() function has completed
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("%s Error reading file containing all URLs %s: %s\n", redMinus, filePath, err)
		os.Exit(1)
	}
	return lines
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("domain", "d", "", "Provide the domain excluding the protocol (http/s://).")
	rootCmd.PersistentFlags().StringP("domainList", "D", "", "Provide the list of domain names excluding the protocol (http/s://).")
}
