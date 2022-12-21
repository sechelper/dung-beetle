package linux

import (
	"dung-beetle/core"
	"dung-beetle/core/utils"
	"fmt"
	"github.com/go-gota/gota/dataframe"
	"github.com/go-gota/gota/series"
	"github.com/gocarina/gocsv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var authCreation = core.Creation{
	Name:   "authAudit",
	Author: "君师",
	Time:   time.Time{},
}

func (authAuditors authAuditors) Creation() *core.Creation {
	return &authCreation
}

// AuthLogLine auth.log 每行日志记录
type AuthLogLine struct {
	Time     string
	Hostname string
	Service  string
	User     string
	Address  string
	Program  string
}

// TryAuthLogin 尝试登入信息
type TryAuthLogin struct {
	User  string
	Count int
	Rank  int
}

// AuthAudit 攻击者信息
type AuthAudit struct {
	Address     string
	Count       int
	Rank        int
	GeoIP2      core.GeoIP2
	TryAuthLogs []TryAuthLogin // 尝试登入时使用的的信息
}

type AuthAuditData struct {
	AuthLogLines []AuthLogLine
	AuthAudits   []AuthAudit
	TryAuthLogs  []TryAuthLogin
}

type authAuditors struct {
	persistent *core.Persistent
	input      *core.Input
}

func NewAuthAudit(input *core.Input, persistent *core.Persistent) core.IAudit {
	return &authAuditors{
		persistent,
		input,
	}
}

var DefaultAuthAuditInput = core.Input{
	Args: []string{"/var/log/auth1.log"},
}

func NewDefaultAuthAudit() core.IAudit {
	return &authAuditors{
		&core.DefaultPersistent,
		&DefaultAuthAuditInput,
	}
}

func (authAuditors authAuditors) Report(auditData interface{}) error {
	authLogAudit := auditData.(*AuthAuditData)
	csvAuthLogLines, err := os.OpenFile(filepath.Join(authAuditors.persistent.Folder, "auth-log.csv"), os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer csvAuthLogLines.Close()

	authLogLinesWriter := gocsv.DefaultCSVWriter(csvAuthLogLines)

	err = authLogLinesWriter.Write([]string{
		"time",
		"hostname",
		"service",
		"user",
		"address",
		"program",
	})
	if err != nil {
		return err
	}

	// auth 原始记录
	for _, authLogLine := range authLogAudit.AuthLogLines {
		err = authLogLinesWriter.Write([]string{
			authLogLine.Time,
			authLogLine.Hostname,
			authLogLine.Service,
			authLogLine.User,
			authLogLine.Address,
			authLogLine.Program,
		})
		if err != nil {
			return err
		}
	}

	authLogLinesWriter.Flush()

	csvAuthAudits, err := os.OpenFile(filepath.Join(authAuditors.persistent.Folder, "auth-audit.csv"), os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer csvAuthAudits.Close()

	csvAuthAuditsWriter := gocsv.DefaultCSVWriter(csvAuthAudits)
	err = csvAuthAuditsWriter.Write([]string{
		"rank",
		"address",
		"count",
		"location",
		"isp",
		"organization",
		"country code",
		"network",
		"domain",
	})
	if err != nil {
		return err
	}

	// TODO GeoIP2 查询

	// 审计报告：记录攻击者地址，从高到底排序
	for _, authLogAudit := range authLogAudit.AuthAudits {
		err = csvAuthAuditsWriter.Write([]string{
			strconv.Itoa(authLogAudit.Rank),
			authLogAudit.Address,
			strconv.Itoa(authLogAudit.Count),
			authLogAudit.GeoIP2.Location,
			authLogAudit.GeoIP2.ISP,
			authLogAudit.GeoIP2.Organization,
			authLogAudit.GeoIP2.CountryCode,
			authLogAudit.GeoIP2.Network,
			authLogAudit.GeoIP2.Domain,
		})
		if err != nil {
			return err
		}
	}

	csvAuthAuditsWriter.Flush()

	csvTryAuthLogs, err := os.OpenFile(filepath.Join(authAuditors.persistent.Folder, "auth-users.csv"), os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer csvTryAuthLogs.Close()

	csvTryAuthLogsWriter := gocsv.DefaultCSVWriter(csvTryAuthLogs)
	err = csvTryAuthLogsWriter.Write([]string{
		"rank",
		"user",
		"count",
	})
	if err != nil {
		return err
	}

	// 审计报告：记录爆破用户，从高到底排序
	for _, tryAuthLog := range authLogAudit.TryAuthLogs {
		err = csvTryAuthLogsWriter.Write([]string{
			strconv.Itoa(tryAuthLog.Rank),
			tryAuthLog.User,
			strconv.Itoa(tryAuthLog.Count),
		})
		if err != nil {
			return err
		}
	}

	csvTryAuthLogsWriter.Flush()
	return nil
}

func authAuditFrame(authLogLines []AuthLogLine) interface{} {
	authAuditData := new(AuthAuditData)
	authAuditData.AuthLogLines = authLogLines

	df := dataframe.LoadStructs(authLogLines)

	// 根据Address字段分组查询，Address字段重复计数，统计单个IP爆破登入次数
	adrDfMaps := df.GroupBy("Address").Aggregation([]dataframe.AggregationType{dataframe.Aggregation_COUNT},
		[]string{"Address"}).Arrange(
		dataframe.RevSort("Address_COUNT")).Maps()
	for rank, auth := range adrDfMaps {

		tryAuthLogs := make([]TryAuthLogin, 0)
		// 统计一个地址都有那些用户尝试登入
		userDf := df.Filter(dataframe.F{
			Colname:    "Address",
			Comparator: series.Eq,
			Comparando: auth["Address"],
		}).GroupBy("User").Aggregation([]dataframe.AggregationType{dataframe.Aggregation_COUNT},
			[]string{"User"}).Arrange(dataframe.RevSort("User_COUNT")).Maps()

		for userRank, user := range userDf {
			tryAuthLogs = append(tryAuthLogs, TryAuthLogin{
				User:  user["User"].(string),
				Count: int(user["User_COUNT"].(float64)),
				Rank:  userRank + 1,
			})
		}
		authAuditData.AuthAudits = append(authAuditData.AuthAudits, AuthAudit{
			Address:     auth["Address"].(string),
			Count:       int(auth["Address_COUNT"].(float64)),
			Rank:        rank + 1,
			TryAuthLogs: tryAuthLogs,
		})
	}

	userDf := df.GroupBy("User").Aggregation([]dataframe.AggregationType{dataframe.Aggregation_COUNT},
		[]string{"User"}).Arrange(dataframe.RevSort("User_COUNT")).Maps()
	for rank, auth := range userDf {
		authAuditData.TryAuthLogs = append(authAuditData.TryAuthLogs, TryAuthLogin{
			auth["User"].(string),
			int(auth["User_COUNT"].(float64)),
			rank + 1,
		})
	}
	return authAuditData

}

func (authAuditors authAuditors) Print(auditData interface{}) {
	//TODO implement me
	fmt.Println("TODO implement me")
}

func (authAuditors authAuditors) Start() (interface{}, error) {
	authLogLines := make([]AuthLogLine, 0)
	paths := authAuditors.input.Args.([]string)
	for logIndex := range paths {
		authLog, _ := utils.ReadLines(paths[logIndex])
		for i := range authLog {
			var authLogLine AuthLogLine
			// Failed password
			if strings.Contains(authLog[i], "Failed password for") {
				// Dec  2 13:31:06 localhost sshd[62472]: Failed password for invalid user fred from 143.198.104.9 port 35928 ssh2
				line := strings.Split(authLog[i], " ")
				lineLen := len(line)
				switch lineLen {
				case 16:
					{
						// Nov 27 00:00:12 localhost sshd[2981199]: Failed password for invalid user maja from 167.99.135.53 port 42336 ssh2
						authLogLine = AuthLogLine{
							authLog[i][:15],
							line[3],
							strings.Split(line[4], "[")[0],
							line[10],
							line[lineLen-4],
							line[lineLen-1],
						}
						authLogLines = append(authLogLines, authLogLine)
					}

				case 17:
					{
						// Dec  1 00:02:32 localhost sshd[3918898]: Failed password for invalid user impala from 104.248.94.181 port 55976 ssh2
						authLogLine = AuthLogLine{
							authLog[i][:15],
							line[4],
							strings.Split(line[5], "[")[0],
							line[lineLen-6],
							line[lineLen-4],
							line[lineLen-1],
						}
						authLogLines = append(authLogLines, authLogLine)
					}
				case 14:
					{
						// Nov 27 00:00:05 localhost sshd[2981097]: Failed password for root from 122.175.4.186 port 48650 ssh2
						authLogLine = AuthLogLine{
							authLog[i][:15],
							line[3],
							strings.Split(line[4], "[")[0],
							line[lineLen-6],
							line[lineLen-4],
							line[lineLen-1],
						}
						authLogLines = append(authLogLines, authLogLine)
					}
				case 15:
					{
						// Dec  1 05:01:40 localhost sshd[3962610]: Failed password for ubuntu from 185.247.206.56 port 48912 ssh2
						authLogLine = AuthLogLine{
							authLog[i][:15],
							line[4],
							strings.Split(line[5], "[")[0],
							line[lineLen-6],
							line[lineLen-4],
							line[lineLen-1],
						}
						authLogLines = append(authLogLines, authLogLine)
					}
				default:
					// Nov 27 04:23:56 localhost sshd[3022545]: message repeated 2 times: [ Failed password for invalid user test5 from 91.212.166.22 port 46474 ssh2]
					hostname := line[3]
					program := strings.Split(line[4], "[")[0]
					if line[1] == "" {
						hostname = line[4]
						program = strings.Split(line[5], "[")[0]
					}
					authLogLine = AuthLogLine{
						authLog[i][:15],
						hostname,
						strings.Replace(line[lineLen-1], "]", "", -1),
						line[lineLen-6],
						line[lineLen-4],
						program,
					}
					authLogLines = append(authLogLines, authLogLine)
				}
			}
		}
	}

	return authAuditFrame(authLogLines), nil
}
