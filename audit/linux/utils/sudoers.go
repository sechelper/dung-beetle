package utils

import (
	"bufio"
	"fmt"
	"os"
	re "regexp"
	"strings"
)

type PRIVILEGE string

const (
	REQUIRED       = iota // 需要密码
	AUTHENTICATION        // 可直接提权
	NONE                  // 不可提权
)

type SudoerEntry struct {
	Op    string
	Runas string
	Cmds  string
}

type ISudoersHandler interface {
	Load() ([]SudoerEntry, error)
	ParseSudoersLine(line *string) (SudoerEntry, error)
}

func NewLoadSudoersHandler(path string) ISudoersHandler {
	return LoadSudoersHandler{path: path}
}

func NewDefaultSudoersHandler() ISudoersHandler {
	return LoadSudoersHandler{path: "/etc/sudoers"}
}

type LoadSudoersHandler struct {
	path string
}

func (s LoadSudoersHandler) Load() ([]SudoerEntry, error) {
	sudoers := make([]SudoerEntry, 0)
	readFile, err := os.Open(s.path)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sudoerEntry, err := s.ParseSudoersLine(&line)
		if err != nil {
			return nil, err
		}
		if sudoerEntry.Op == "" {
			continue
		}
		sudoers = append(sudoers, sudoerEntry)
	}

	readFile.Close()
	return sudoers, nil
}

func (s LoadSudoersHandler) ParseSudoersLine(line *string) (SudoerEntry, error) {
	sudoerEntry := SudoerEntry{}
	sudoerCompile := re.MustCompile(`\s+`)
	sudoerRaw := sudoerCompile.Split(*line, -1)
	if len(sudoerRaw) == 3 {
		sudoerEntry = SudoerEntry{
			Op:    sudoerRaw[0],
			Runas: sudoerRaw[1],
			Cmds:  sudoerRaw[2],
		}
	}
	return sudoerEntry, nil
}
