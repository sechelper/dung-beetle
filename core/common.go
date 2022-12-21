package core

type Input struct {
	Args interface{}
}

const (
	REMOTE = iota
	LOCAL
)

type FileHandler interface {
	Save(files []string)
}

type Persistent struct {
	T           int //存储方式 REMOTE | LOCAL
	Folder      string
	FileHandler FileHandler // TODO
}

var DefaultPersistent = Persistent{
	T:           LOCAL,
	Folder:      "/tmp/data",
	FileHandler: nil,
}
