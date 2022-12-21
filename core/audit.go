package core

type IAudit interface {
	Creation() *Creation
	Start() (interface{}, error)
	Report(auditData interface{}) error
	Print(auditData interface{})
}
