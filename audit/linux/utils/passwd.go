package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type PasswdEntry struct {
	Username string
	Passwd   string
	Uid      int
	Gid      int
	Info     string
	Homedir  string
	Shell    string
}

type IPasswdHandler interface {
	Load() ([]PasswdEntry, error)
	ParsePasswdLine(line *string) (PasswdEntry, error)
}

type PasswdHandler struct {
	path string
}

func NewPasswdHandler(path string) IPasswdHandler {
	return PasswdHandler{path: path}
}

func NewDefaultPasswdHandler() IPasswdHandler {
	return PasswdHandler{path: "/etc/passwd"}
}

func (ph PasswdHandler) ParsePasswdLine(line *string) (PasswdEntry, error) {
	result := PasswdEntry{}
	parts := strings.Split(strings.TrimSpace(*line), ":")
	if len(parts) != 7 {
		return result, fmt.Errorf("Passwd line had wrong number of parts %d != 7", len(parts))
	}
	result.Username = strings.TrimSpace(parts[0])
	result.Passwd = strings.TrimSpace(parts[1])

	uid, err := strconv.Atoi(parts[2])
	if err != nil {
		return result, fmt.Errorf("Passwd line had badly formatted uid %s", parts[2])
	}
	result.Uid = uid

	gid, err := strconv.Atoi(parts[3])
	if err != nil {
		return result, fmt.Errorf("Passwd line had badly formatted gid %s", parts[2])
	}
	result.Gid = gid

	result.Info = strings.TrimSpace(parts[4])
	result.Homedir = strings.TrimSpace(parts[5])
	result.Shell = strings.TrimSpace(parts[6])
	return result, nil
}

func (ph PasswdHandler) Load() ([]PasswdEntry, error) {
	passwds := make([]PasswdEntry, 0)
	readFile, err := os.Open(ph.path)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		passwdEntry, err := ph.ParsePasswdLine(&line)
		if err != nil {
			return nil, err
		}
		passwds = append(passwds, passwdEntry)
	}

	readFile.Close()
	return passwds, nil
}
