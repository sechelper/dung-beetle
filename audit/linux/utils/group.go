package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type GroupEntry struct {
	Name     string
	Password string
	Gid      int
	GUsers   []string
}

type IGroupHandler interface {
	Load() (map[int]GroupEntry, error)
	ParseGroupLine(line *string) (GroupEntry, error)
}

type GroupHandler struct {
	path string
}

func NewGroupHandler(path string) IGroupHandler {
	return GroupHandler{path: path}
}

func NewDefaultGroupHandler() IGroupHandler {
	return GroupHandler{path: "/etc/group"}
}

func (gh GroupHandler) ParseGroupLine(line *string) (GroupEntry, error) {
	groupEntry := GroupEntry{}
	// adm:x:4:syslog,ubuntu
	group := strings.Split(*line, ":")
	gid, err := strconv.Atoi(group[2])
	if err != nil {
		return groupEntry, err
	}
	groupEntry.Name = group[0]
	groupEntry.Password = group[1]
	groupEntry.Gid = gid
	if group[3] != "" {
		groupEntry.GUsers = strings.Split(group[3], ",")
	}

	return groupEntry, nil
}

func (gh GroupHandler) Load() (map[int]GroupEntry, error) {
	groups := map[int]GroupEntry{}
	readFile, err := os.Open(gh.path)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		groupEntry, err := gh.ParseGroupLine(&line)
		if err != nil {
			return nil, err
		}
		groups[groupEntry.Gid] = groupEntry
	}

	readFile.Close()
	return groups, nil
}
