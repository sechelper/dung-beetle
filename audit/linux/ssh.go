package linux

import (
	"dung-beetle/core"
	"fmt"
	"time"
)

var sshAuditCreation = core.Creation{
	Name:   "ssh audit",
	Author: "君师",
	Time:   time.Time{},
}

func (auditors sshAuditors) Creation() *core.Creation {
	return &sshAuditCreation
}

type sshAuditors struct {
	persistent *core.Persistent
	input      *core.Input
}

func NewSshAuditors(input *core.Input, persistent *core.Persistent) core.IAudit {
	return &authAuditors{
		persistent,
		input,
	}
}

func (auditors sshAuditors) Report(auditData interface{}) error {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil
}

func (auditors sshAuditors) Print(auditData interface{}) {
	//TODO implement me
	fmt.Println("TODO implement me")
}

func (auditors sshAuditors) Start() (interface{}, error) {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil, nil
}
