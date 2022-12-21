package linux

import (
	"dung-beetle/audit/linux/utils"
	"dung-beetle/core"
	"dung-beetle/third-party/capability"
	"fmt"
	"log"
	"time"
)

var privilegeAuditCreation = core.Creation{
	Name:   "privilege audit",
	Author: "君师",
	Time:   time.Time{},
}

func (auditors privilegeAuditors) Creation() *core.Creation {
	return &privilegeAuditCreation
}

type privilegeAuditors struct {
	persistent *core.Persistent
	input      *core.Input
}

func NewPrivilegeAuditors(input *core.Input, persistent *core.Persistent) core.IAudit {
	return &authAuditors{
		persistent,
		input,
	}
}

func (auditors privilegeAuditors) Report(auditData interface{}) error {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil
}

func (auditors privilegeAuditors) Print(auditData interface{}) {
	//TODO implement me
	fmt.Println("TODO implement me")
}

func (auditors privilegeAuditors) Start() (interface{}, error) {
	//TODO implement me
	fmt.Println("TODO implement me")
	return nil, nil
}

// capabilityPrivilegeAudit 找到具备capability提权特征的程序
func capabilityPrivilegeAudit() []string {
	privilegePrograms := make([]string, 0)
	dirs, err := utils.FilePathWalkDir("/")
	if err != nil {
		log.Fatal(err)
	}
	for i := range dirs {
		file2, err := capability.NewFile2(dirs[i])
		if err != nil {
			log.Fatal(err)
		}
		file2.Load()
		if file2.StringCap(capability.PERMITTED) == "setuid" {
			privilegePrograms = append(privilegePrograms, dirs[i])
		}
	}
	return privilegePrograms
}
