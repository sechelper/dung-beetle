package linux

import (
	"dung-beetle/audit/linux/utils"
	"dung-beetle/core"
	"fmt"
	"strings"
	"time"
)

var userAuditCreation = core.Creation{
	Name:   "user audit",
	Author: "君师",
	Time:   time.Time{},
}

func (userAuditors userAuditors) Creation() *core.Creation {
	return &userAuditCreation
}

type userAuditors struct {
	persistent *core.Persistent
	input      *core.Input
}

func NewUserAuditors(input *core.Input, persistent *core.Persistent) core.IAudit {
	return &userAuditors{
		persistent,
		input,
	}
}

var DefaultUserAuditInput = core.Input{
	Args: UserAuditInput{passwd: "/etc/passwd", group: "/etc/group"},
}

func NewUserDefaultAuditors() core.IAudit {
	return &userAuditors{
		&core.DefaultPersistent,
		&DefaultUserAuditInput,
	}
}

type UserAuditInput struct {
	passwd string
	group  string
}

type UserAudit struct {
	Login  bool
	Passwd utils.PasswdEntry
	Group  utils.GroupEntry
	Sudoer utils.SudoerEntry
}

type UserAuditData struct {
	passwds []utils.PasswdEntry
	groups  map[int]utils.GroupEntry
	sudoers []utils.SudoerEntry
}

// Report ref: https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
func (userAuditors userAuditors) Report(auditData interface{}) error {
	// {"login":true, "passwd": PasswdEntry, "group": GroupEntry, "sudo":REQUIRED}
	groups := auditData.(UserAuditData).groups
	passwds := auditData.(UserAuditData).passwds
	sudoers := auditData.(UserAuditData).sudoers
	for i := range passwds {
		// TODO
		// 可登入账户
		userAudit := UserAudit{
			Login:  false,
			Passwd: passwds[i],
			Group:  groups[passwds[i].Gid],
		}
		if !(strings.HasSuffix(passwds[i].Shell, "nologin") ||
			strings.HasSuffix(passwds[i].Shell, "false") ||
			strings.HasSuffix(passwds[i].Shell, "sync")) {
			userAudit.Login = true

		}
		// 具备sudo账户\账户组
		for i := range sudoers {
			if strings.HasPrefix(sudoers[i].Op, "%") && strings.HasSuffix(sudoers[i].Op, userAudit.Group.Name) {
				userAudit.Sudoer = sudoers[i]
			}
		}
		fmt.Println(userAudit)
	}

	return nil
}

func (userAuditors userAuditors) Print(auditData interface{}) {
	//TODO implement me
	fmt.Println("TODO implement me")
}

func (userAuditors userAuditors) Start() (interface{}, error) {
	userAuditInput := userAuditors.input.Args.(UserAuditInput)
	userAuditData := UserAuditData{}
	// 检查passwd，筛选可登入和具备特权的账户

	// /etc/passwd
	passwdHandler := utils.NewPasswdHandler(userAuditInput.passwd)
	passwds, err := passwdHandler.Load()

	if err != nil {
		return nil, err
	}
	userAuditData.passwds = passwds

	// /etc/group
	groupHandler := utils.NewDefaultGroupHandler()
	groups, err := groupHandler.Load()
	if err != nil {
		return nil, err
	}

	userAuditData.groups = groups

	// /etc/sudoers
	sudodersHandler := utils.NewDefaultSudoersHandler()
	sudoers, err := sudodersHandler.Load()
	if err != nil {
		return nil, err
	}

	userAuditData.sudoers = sudoers

	return userAuditData, nil
}
