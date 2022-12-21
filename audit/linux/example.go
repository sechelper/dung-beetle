package linux

import (
	"dung-beetle/core"
	"fmt"
	"time"
)

var exampleAuditCreation = core.Creation{
	Name:   "example audit",
	Author: "君师",
	Time:   time.Time{},
}

func (auditors exampleAuditors) Creation() *core.Creation {
	return &exampleAuditCreation
}

type exampleAuditors struct {
	persistent *core.Persistent
	input      *core.Input
}

func NewExampleAuditors(input *core.Input, persistent *core.Persistent) core.IAudit {
	return &authAuditors{
		persistent,
		input,
	}
}

func (auditors exampleAuditors) Report(auditData interface{}) error {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil
}

func (auditors exampleAuditors) Print(auditData interface{}) {
	//TODO implement me
	fmt.Println("TODO implement me")
}

func (auditors exampleAuditors) Start() (interface{}, error) {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil, nil
}
