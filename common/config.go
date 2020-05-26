/*
 * Copyright 2018 Xiaomi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v2"
)

var (
	// BlackList 黑名单中的SQL不会被评审
	BlackList []string
	// PrintConfig -print-config
	PrintConfig bool
	// PrintVersion -print-config
	PrintVersion bool
	// CheckConfig -check-config
	CheckConfig bool
	// 防止 readCmdFlags 函数重入
	hasParsed bool
)

// Configuration 配置文件定义结构体
type Configuration struct {
	// +++++++++++++++测试环境+++++++++++++++++
	OnlineDSN               *Dsn   `yaml:"online-dsn"`                // 线上环境数据库配置
	TestDSN                 *Dsn   `yaml:"test-dsn"`                  // 测试环境数据库配置
	AllowOnlineAsTest       bool   `yaml:"allow-online-as-test"`      // 允许 Online 环境也可以当作 Test 环境
	DropTestTemporary       bool   `yaml:"drop-test-temporary"`       // 是否清理Test环境产生的临时库表
	CleanupTestDatabase     bool   `yaml:"cleanup-test-database"`     // 清理残余的测试数据库（程序异常退出或未开启drop-test-temporary）  issue #48
	OnlySyntaxCheck         bool   `yaml:"only-syntax-check"`         // 只做语法检查不输出优化建议
	SamplingStatisticTarget int    `yaml:"sampling-statistic-target"` // 数据采样因子，对应 PostgreSQL 的 default_statistics_target
	Sampling                bool   `yaml:"sampling"`                  // 数据采样开关
	SamplingCondition       string `yaml:"sampling-condition"`        // 指定采样条件，如：WHERE xxx LIMIT xxx;
	Profiling               bool   `yaml:"profiling"`                 // 在开启数据采样的情况下，在测试环境执行进行profile
	Trace                   bool   `yaml:"trace"`                     // 在开启数据采样的情况下，在测试环境执行进行Trace
	Explain                 bool   `yaml:"explain"`                   // Explain开关
	Delimiter               string `yaml:"delimiter"`                 // SQL分隔符

	// +++++++++++++++日志相关+++++++++++++++++
	// 日志级别，这里使用了 beego 的 log 包
	// [0:Emergency, 1:Alert, 2:Critical, 3:Error, 4:Warning, 5:Notice, 6:Informational, 7:Debug]
	LogLevel int `yaml:"log-level"`
	// 日志输出位置，默认日志输出到控制台
	// 目前只支持['console', 'file']两种形式，如非console形式这里需要指定文件的路径，可以是相对路径
	LogOutput string `yaml:"log-output"`
	// 优化建议输出格式，目前支持: json, text, markdown格式，如指定其他格式会给 pretty.Println 的输出
	ReportType string `yaml:"report-type"`
	// 当 ReportType 为 html 格式时使用的 css 风格，如不指定会提供一个默认风格。CSS可 以是本地文件，也可以是一个URL
	ReportCSS string `yaml:"report-css"`
	// 当 ReportType 为 html 格式时使用的 javascript 脚本，如不指定默认会加载SQL pretty 使用的 javascript。像CSS一样可以是本地文件，也可以是一个URL
	ReportJavascript string `yaml:"report-javascript"`
	// 当ReportType 为 html 格式时，HTML 的 title
	ReportTitle string `yaml:"report-title"`
	// blackfriday markdown2html config
	MarkdownExtensions int `yaml:"markdown-extensions"` // markdown 转 html 支持的扩展包, 参考blackfriday
	MarkdownHTMLFlags  int `yaml:"markdown-html-flags"` // markdown 转 html 支持的 flag, 参考blackfriday, default 0

	// ++++++++++++++优化建议相关++++++++++++++
	IgnoreRules          []string `yaml:"ignore-rules"`              // 忽略的优化建议规则
	RewriteRules         []string `yaml:"rewrite-rules"`             // 生效的重写规则
	BlackList            string   `yaml:"blacklist"`                 // blacklist 中的 SQL 不会被评审，可以是指纹，也可以是正则
	MaxJoinTableCount    int      `yaml:"max-join-table-count"`      // 单条 SQL 中 JOIN 表的最大数量
	MaxGroupByColsCount  int      `yaml:"max-group-by-cols-count"`   // 单条 SQL 中 GroupBy 包含列的最大数量
	MaxDistinctCount     int      `yaml:"max-distinct-count"`        // 单条 SQL 中 Distinct 的最大数量
	MaxIdxColsCount      int      `yaml:"max-index-cols-count"`      // 复合索引中包含列的最大数量
	MaxTextColsCount     int      `yaml:"max-text-cols-count"`       // 表中含有的 text/blob 列的最大数量
	MaxTotalRows         uint64   `yaml:"max-total-rows"`            // 计算散粒度时，当数据行数大于 MaxTotalRows 即开启数据库保护模式，散粒度返回结果可信度下降
	MaxQueryCost         int64    `yaml:"max-query-cost"`            // last_query_cost 超过该值时将给予警告
	SpaghettiQueryLength int      `yaml:"spaghetti-query-length"`    // SQL最大长度警告，超过该长度会给警告
	AllowDropIndex       bool     `yaml:"allow-drop-index"`          // 允许输出删除重复索引的建议
	MaxInCount           int      `yaml:"max-in-count"`              // IN()最大数量
	MaxIdxBytesPerColumn int      `yaml:"max-index-bytes-percolumn"` // 索引中单列最大字节数，默认767
	MaxIdxBytes          int      `yaml:"max-index-bytes"`           // 索引总长度限制，默认3072
	AllowCharsets        []string `yaml:"allow-charsets"`            // 允许使用的 DEFAULT CHARSET
	AllowCollates        []string `yaml:"allow-collates"`            // 允许使用的 COLLATE
	AllowEngines         []string `yaml:"allow-engines"`             // 允许使用的存储引擎
	MaxIdxCount          int      `yaml:"max-index-count"`           // 单张表允许最多索引数
	MaxColCount          int      `yaml:"max-column-count"`          // 单张表允许最大列数
	MaxValueCount        int      `yaml:"max-value-count"`           // INSERT/REPLACE 单次允许批量写入的行数
	IdxPrefix            string   `yaml:"index-prefix"`              // 普通索引建议使用的前缀
	UkPrefix             string   `yaml:"unique-key-prefix"`         // 唯一键建议使用的前缀
	MaxSubqueryDepth     int      `yaml:"max-subquery-depth"`        // 子查询最大尝试
	MaxVarcharLength     int      `yaml:"max-varchar-length"`        // varchar最大长度
	ColumnNotAllowType   []string `yaml:"column-not-allow-type"`     // 字段不允许使用的数据类型
	MinCardinality       float64  `yaml:"min-cardinality"`           // 添加索引散粒度阈值，范围 0~100

	// ++++++++++++++EXPLAIN检查项+++++++++++++
	ExplainSQLReportType   string   `yaml:"explain-sql-report-type"`  // EXPLAIN markdown 格式输出 SQL 样式，支持 sample, fingerprint, pretty 等
	ExplainType            string   `yaml:"explain-type"`             // EXPLAIN方式 [traditional, extended, partitions]
	ExplainFormat          string   `yaml:"explain-format"`           // FORMAT=[json, traditional]
	ExplainWarnSelectType  []string `yaml:"explain-warn-select-type"` // 哪些 select_type 不建议使用
	ExplainWarnAccessType  []string `yaml:"explain-warn-access-type"` // 哪些 access type 不建议使用
	ExplainMaxKeyLength    int      `yaml:"explain-max-keys"`         // 最大 key_len
	ExplainMinPossibleKeys int      `yaml:"explain-min-keys"`         // 最小 possible_keys 警告
	ExplainMaxRows         int      `yaml:"explain-max-rows"`         // 最大扫描行数警告
	ExplainWarnExtra       []string `yaml:"explain-warn-extra"`       // 哪些 extra 信息会给警告
	ExplainMaxFiltered     float64  `yaml:"explain-max-filtered"`     // filtered 大于该配置给出警告
	ExplainWarnScalability []string `yaml:"explain-warn-scalability"` // 复杂度警告名单
	ShowWarnings           bool     `yaml:"show-warnings"`            // explain extended with show warnings
	ShowLastQueryCost      bool     `yaml:"show-last-query-cost"`     // switch with show status like 'last_query_cost'
	// ++++++++++++++其他配置项+++++++++++++++
	Query              string `yaml:"query"`                 // 需要进行调优的SQL
	ListHeuristicRules bool   `yaml:"list-heuristic-rules"`  // 打印支持的评审规则列表
	ListRewriteRules   bool   `yaml:"list-rewrite-rules"`    // 打印重写规则
	ListTestSqls       bool   `yaml:"list-test-sqls"`        // 打印测试case用于测试
	ListReportTypes    bool   `yaml:"list-report-types"`     // 打印支持的报告输出类型
	Verbose            bool   `yaml:"verbose"`               // verbose模式，会多输出一些信息
	DryRun             bool   `yaml:"dry-run"`               // 是否在预演环境执行
	MaxPrettySQLLength int    `yaml:"max-pretty-sql-length"` // 超出该长度的SQL会转换成指纹输出
}

// Config 默认设置
var Config = &Configuration{
	OnlineDSN:               newDSN(nil),
	TestDSN:                 newDSN(nil),
	AllowOnlineAsTest:       false,
	DropTestTemporary:       true,
	CleanupTestDatabase:     false,
	DryRun:                  true,
	OnlySyntaxCheck:         false,
	SamplingStatisticTarget: 100,
	Sampling:                false,
	Profiling:               false,
	Trace:                   false,
	Explain:                 true,
	Delimiter:               ";",
	MinCardinality:          0,

	MaxJoinTableCount:    5,
	MaxGroupByColsCount:  5,
	MaxDistinctCount:     5,
	MaxIdxColsCount:      5,
	MaxTextColsCount:     2,
	MaxIdxBytesPerColumn: 767,
	MaxIdxBytes:          3072,
	MaxTotalRows:         9999999,
	MaxQueryCost:         9999,
	SpaghettiQueryLength: 2048,
	AllowDropIndex:       false,
	LogLevel:             3,
	LogOutput:            "soar.log",
	ReportType:           "markdown",
	ReportCSS:            "",
	ReportJavascript:     "",
	ReportTitle:          "SQL优化分析报告",
	BlackList:            "",
	AllowCharsets:        []string{"utf8", "utf8mb4"},
	AllowCollates:        []string{},
	AllowEngines:         []string{"innodb"},
	MaxIdxCount:          10,
	MaxColCount:          40,
	MaxValueCount:        100,
	MaxInCount:           10,
	IdxPrefix:            "idx_",
	UkPrefix:             "uk_",
	MaxSubqueryDepth:     5,
	MaxVarcharLength:     1024,
	ColumnNotAllowType:   []string{"boolean"},

	MarkdownExtensions: 94,
	MarkdownHTMLFlags:  0,

	ExplainSQLReportType:   "pretty",
	ExplainType:            "extended",
	ExplainFormat:          "traditional",
	ExplainWarnSelectType:  []string{""},
	ExplainWarnAccessType:  []string{"ALL"},
	ExplainMaxKeyLength:    3,
	ExplainMinPossibleKeys: 0,
	ExplainMaxRows:         10000,
	ExplainWarnExtra:       []string{"Using temporary", "Using filesort"},
	ExplainMaxFiltered:     100.0,
	ExplainWarnScalability: []string{"O(n)"},
	ShowWarnings:           false,
	ShowLastQueryCost:      false,

	IgnoreRules: []string{
		"COL.011",
	},
	RewriteRules: []string{
		"delimiter",
		"orderbynull",
		"groupbyconst",
		"dmlorderby",
		"having",
		"star2columns",
		"insertcolumns",
		"distinctstar",
	},

	ListHeuristicRules: false,
	ListRewriteRules:   false,
	ListTestSqls:       false,
	ListReportTypes:    false,
	MaxPrettySQLLength: 1024,
}

// Dsn Data source name
type Dsn struct {
	User             string            `yaml:"user"`               // Usernames
	Password         string            `yaml:"password"`           // Password (requires User)
	Net              string            `yaml:"net"`                // Network type
	Addr             string            `yaml:"addr"`               // Network address (requires Net)
	Schema           string            `yaml:"schema"`             // Database name
	Charset          string            `yaml:"charset"`            // SET NAMES charset
	Collation        string            `yaml:"collation"`          // Connection collation
	Loc              string            `yaml:"loc"`                // Location for time.Time values
	TLS              string            `yaml:"tls"`                // TLS configuration name
	ServerPubKey     string            `yaml:"server-public-key"`  // Server public key name
	MaxAllowedPacket int               `ymal:"max-allowed-packet"` // Max packet size allowed
	Params           map[string]string `yaml:"params"`             // Other Connection parameters, `SET param=val`, `SET NAMES charset`
	Timeout          int               `yaml:"timeout"`            // Dial timeout
	ReadTimeout      int               `yaml:"read-timeout"`       // I/O read timeout
	WriteTimeout     int               `yaml:"write-timeout"`      // I/O write timeout

	AllowNativePasswords bool `yaml:"allow-native-passwords"` // Allows the native password authentication method
	AllowOldPasswords    bool `yaml:"allow-old-passwords"`    // Allows the old insecure password method

	Disable bool `yaml:"disable"`
	Version int  `yaml:"-"` // 版本自动检查，不可配置
}

// newDSN create default Dsn struct
func newDSN(cfg *mysql.Config) *Dsn {
	dsn := &Dsn{
		Net:                  "tcp",
		Schema:               "information_schema",
		Charset:              "utf8",
		AllowNativePasswords: true,
		Params:               make(map[string]string),
		MaxAllowedPacket:     4 << 20, // 4 MiB

		// Disable: true,
		Version: 99999,
	}
	if cfg == nil {
		return dsn
	}
	dsn.User = cfg.User
	dsn.Password = cfg.Passwd
	dsn.Net = cfg.Net
	dsn.Addr = cfg.Addr
	dsn.Schema = cfg.DBName
	dsn.Params = make(map[string]string)
	for k, v := range cfg.Params {
		dsn.Params[k] = v
	}
	if _, ok := cfg.Params["charset"]; ok {
		dsn.Charset = cfg.Params["charset"]
	}
	dsn.Collation = cfg.Collation
	dsn.Loc = cfg.Loc.String()
	dsn.MaxAllowedPacket = cfg.MaxAllowedPacket
	dsn.ServerPubKey = cfg.ServerPubKey
	dsn.TLS = cfg.TLSConfig
	dsn.Timeout = int(cfg.Timeout / time.Second)
	dsn.ReadTimeout = int(cfg.ReadTimeout / time.Second)
	dsn.WriteTimeout = int(cfg.WriteTimeout / time.Second)
	dsn.AllowNativePasswords = cfg.AllowNativePasswords
	dsn.AllowOldPasswords = cfg.AllowOldPasswords
	return dsn
}

// newMySQLConfig convert Dsn to go-sql-drive Config
func (env *Dsn) newMySQLConifg() (*mysql.Config, error) {
	var err error
	dsn := mysql.NewConfig()

	dsn.User = env.User
	dsn.Passwd = env.Password
	dsn.Net = env.Net
	dsn.Addr = env.Addr
	dsn.DBName = env.Schema
	dsn.Params = make(map[string]string)
	for k, v := range env.Params {
		dsn.Params[k] = v
	}
	dsn.Params["charset"] = env.Charset
	dsn.Collation = env.Collation
	dsn.Loc, err = time.LoadLocation(env.Loc)
	if err != nil {
		return nil, err
	}
	dsn.MaxAllowedPacket = env.MaxAllowedPacket
	dsn.ServerPubKey = env.ServerPubKey
	dsn.TLSConfig = env.TLS
	dsn.Timeout = time.Duration(env.Timeout) * time.Second
	dsn.ReadTimeout = time.Duration(env.ReadTimeout) * time.Second
	dsn.WriteTimeout = time.Duration(env.WriteTimeout) * time.Second
	dsn.AllowNativePasswords = env.AllowNativePasswords
	dsn.AllowOldPasswords = env.AllowOldPasswords
	return dsn, err
}

// 解析命令行DSN输入
func parseDSN(odbc string, d *Dsn) *Dsn {
	dsn := newDSN(nil)
	var addr, user, password, schema, charset string
	if odbc == FormatDSN(d) {
		return d
	}

	if d != nil {
		// 原来有个判断，后来判断条件被删除了就导致第一次addr无论如何都会被修改。所以这边先注释掉
		// addr = d.Addr
		user = d.User
		password = d.Password
		schema = d.Schema
		charset = d.Charset
	}

	// 设置为空表示禁用环境
	odbc = strings.TrimSpace(odbc)
	if odbc == "" {
		return &Dsn{Disable: true}
	}

	var userInfo, hostInfo, query string

	// DSN 格式匹配
	if res := regexp.MustCompile(`^(.*)@(.*?)/(.*?)($|\?)(.*)`).FindStringSubmatch(odbc); len(res) > 5 {
		// userInfo@hostInfo/database
		userInfo = res[1]
		hostInfo = res[2]
		schema = res[3]
		query = res[5]
	} else if res := regexp.MustCompile(`^(.*)/(.*?)($|\?)(.*)`).FindStringSubmatch(odbc); len(res) > 4 {
		// hostInfo/database
		hostInfo = res[1]
		schema = res[2]
		query = res[4]
	} else if res := regexp.MustCompile(`^(.*)@(.*?)($|\?)(.*)`).FindStringSubmatch(odbc); len(res) > 4 {
		// userInfo@hostInfo
		userInfo = res[1]
		hostInfo = res[2]
		query = res[4]
	} else if res := regexp.MustCompile(`^(.*?)($|\?)(.*)`).FindStringSubmatch(odbc); len(res) > 3 {
		// hostInfo
		hostInfo = res[1]
		query = res[3]
	}

	// 解析用户信息
	if userInfo != "" {
		user = strings.Split(userInfo, ":")[0]
		// 防止密码中含有与用户名相同的字符, 所以用正则替换, 剩下的就是密码
		password = strings.TrimLeft(regexp.MustCompile("^"+user).ReplaceAllString(userInfo, ""), ":")
	}

	// 解析主机信息
	host := strings.Split(hostInfo, ":")[0]
	port := strings.TrimLeft(strings.Replace(hostInfo, host, "", 1), ":")
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "3306"
	}
	addr = host + ":" + port

	// 解析查询字符串
	if query != "" {
		params := strings.Split(query, "&")
		for _, f := range params {
			attr := strings.Split(f, "=")
			if len(attr) > 1 {
				arg := strings.TrimSpace(attr[0])
				val := strings.TrimSpace(attr[1])
				switch arg {
				case "charset":
					charset = val
				default:
				}
			}
		}
	}

	// 默认用information_schema库
	if schema == "" {
		schema = "information_schema"
	}

	// 默认 utf8 使用字符集
	if charset == "" {
		charset = "utf8"
	}

	dsn.Addr = addr
	dsn.User = user
	dsn.Password = password
	dsn.Schema = schema
	dsn.Charset = charset
	return dsn
}

// ParseDSN compatible with old version soar < 0.11.0
func ParseDSN(odbc string, d *Dsn) *Dsn {
	cfg, err := mysql.ParseDSN(odbc)
	if err != nil {
		// Log.Debug("go-sql-driver/mysql.ParseDSN Error: %s, DSN: %s, try to use old version parseDSN", err.Error(), odbc)
		return parseDSN(odbc, d)
	}
	return newDSN(cfg)
}

// FormatDSN 格式化打印DSN
func FormatDSN(env *Dsn) string {
	if env == nil || env.Disable {
		return ""
	}
	dsn, err := env.newMySQLConifg()
	if err != nil {
		return ""
	}
	return dsn.FormatDSN()
}

// SoarVersion soar version information
func SoarVersion() {
	fmt.Println("Version:", Version)
	fmt.Println("Branch:", Branch)
	fmt.Println("Compile:", Compile)
	fmt.Println("GitDirty:", GitDirty)
}

// PrintConfiguration for `-print-config` flag
func PrintConfiguration() {
	// 打印配置的时候密码不显示
	if !Config.Verbose {
		Config.OnlineDSN.Password = "********"
		Config.TestDSN.Password = "********"
	}
	data, _ := yaml.Marshal(Config)
	fmt.Print(string(data))
}

// 加载配置文件
func (conf *Configuration) readConfigFile(path string) error {
	configFile, err := os.Open(path)
	if err != nil {
		Log.Warning("readConfigFile(%s) os.Open failed: %v", path, err)
		return err
	}
	defer configFile.Close()

	content, err := ioutil.ReadAll(configFile)
	if err != nil {
		Log.Warning("readConfigFile(%s) ioutil.ReadAll failed: %v", path, err)
		return err
	}

	err = yaml.Unmarshal(content, Config)
	if err != nil {
		Log.Warning("readConfigFile(%s) yaml.Unmarshal failed: %v", path, err)
		return err
	}
	return nil
}

// ParseConfig 加载配置文件和命令行参数
func ParseConfig(configFile string) error {
	var err error
	var configs []string
	// 指定了配置文件优先读配置文件，未指定配置文件按如下顺序加载，先找到哪个加载哪个
	if configFile == "" {
		configs = []string{
			"/etc/soar.yaml",
			filepath.Join(BaseDir, "etc", "soar.yaml"),
			filepath.Join(BaseDir, "soar.yaml"),
		}
	} else {
		configs = []string{
			configFile,
		}
	}

	for _, config := range configs {
		if _, err = os.Stat(config); err == nil {
			err = Config.readConfigFile(config)
			if err != nil {
				Log.Error("ParseConfig Config.readConfigFile Error: %v", err)
			}
			// LogOutput now is "console", if add Log.Debug here will print into stdout anyway.
			// Log.Debug("ParseConfig use config file: %s", config)
			break
		}
	}

	// parse blacklist & ignore blacklist file parse error
	if _, e := os.Stat(Config.BlackList); e == nil {
		var blFd *os.File
		blFd, err = os.Open(Config.BlackList)
		if err == nil {
			bl := bufio.NewReader(blFd)
			for {
				rule, e := bl.ReadString('\n')
				if e != nil {
					break
				}
				rule = strings.TrimSpace(rule)
				if strings.HasPrefix(rule, "#") || rule == "" {
					continue
				}
				BlackList = append(BlackList, rule)
			}
		}
		defer blFd.Close()
	}
	LoggerInit()
	return err
}

// ReportType 元数据结构定义
type ReportType struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Example     string `json:"Example"`
}

// ReportTypes 命令行-report-type支持的形式
var ReportTypes = []ReportType{
	{
		Name:        "lint",
		Description: "参考sqlint格式，以插件形式集成到代码编辑器，显示输出更加友好",
		Example:     `soar -report-type lint -query test.sql`,
	},
	{
		Name:        "markdown",
		Description: "该格式为默认输出格式，以markdown格式展现，可以用网页浏览器插件直接打开，也可以用markdown编辑器打开",
		Example:     `echo "select * from film" | soar`,
	},
	{
		Name:        "rewrite",
		Description: "SQL重写功能，配合-rewrite-rules参数一起使用，可以通过-list-rewrite-rules 查看所有支持的 SQL 重写规则",
		Example:     `echo "select * from film" | soar -rewrite-rules star2columns,delimiter -report-type rewrite`,
	},
	{
		Name:        "ast",
		Description: "输出 SQL 的抽象语法树，主要用于测试",
		Example:     `echo "select * from film" | soar -report-type ast`,
	},
	{
		Name:        "tiast",
		Description: "输出 SQL 的 TiDB抽象语法树，主要用于测试",
		Example:     `echo "select * from film" | soar -report-type tiast`,
	},
	{
		Name:        "fingerprint",
		Description: "输出SQL的指纹",
		Example:     `echo "select * from film where language_id=1" | soar -report-type fingerprint`,
	},
	{
		Name:        "md2html",
		Description: "markdown 格式转 html 格式小工具",
		Example:     `soar -list-heuristic-rules | soar -report-type md2html > heuristic_rules.html`,
	},
	{
		Name:        "explain-digest",
		Description: "输入为EXPLAIN的表格，JSON 或 Vertical格式，对其进行分析，给出分析结果",
		Example: `soar -report-type explain-digest << EOF
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
| id | select_type | table | type | possible_keys | key  | key_len | ref  | rows | Extra |
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
|  1 | SIMPLE      | film  | ALL  | NULL          | NULL | NULL    | NULL | 1131 |       |
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
EOF`,
	},
	{
		Name:        "duplicate-key-checker",
		Description: "对 OnlineDsn 中指定的 database 进行索引重复检查",
		Example:     `soar -report-type duplicate-key-checker -online-dsn user:password@127.0.0.1:3306/db`,
	},
	{
		Name:        "html",
		Description: "以HTML格式输出报表",
		Example:     `echo "select * from film" | soar -report-type html`,
	},
	{
		Name:        "json",
		Description: "输出JSON格式报表，方便应用程序处理",
		Example:     `echo "select * from film" | soar -report-type json`,
	},
	{
		Name:        "tokenize",
		Description: "对SQL进行切词，主要用于测试",
		Example:     `echo "select * from film" | soar -report-type tokenize`,
	},
	{
		Name:        "compress",
		Description: "SQL压缩小工具，使用内置SQL压缩逻辑，测试中的功能",
		Example: `echo "select
*
from
  film" | soar -report-type compress`,
	},
	{
		Name:        "pretty",
		Description: "使用kr/pretty打印报告，主要用于测试",
		Example:     `echo "select * from film" | soar -report-type pretty`,
	},
	{
		Name:        "remove-comment",
		Description: "去除SQL语句中的注释，支持单行多行注释的去除",
		Example:     `echo "select/*comment*/ * from film" | soar -report-type remove-comment`,
	},
	{
		Name:        "chardet",
		Description: "猜测输入的 SQL 使用的字符集",
		Example:     "echo '中文' | soar -report-type chardet",
	},
}

// ListReportTypes 查看所有支持的report-type
func ListReportTypes() {
	switch Config.ReportType {
	case "json":
		js, err := json.MarshalIndent(ReportTypes, "", "  ")
		if err == nil {
			fmt.Println(string(js))
		}
	default:
		fmt.Print("# 支持的报告类型\n\n[toc]\n\n")
		for _, r := range ReportTypes {
			fmt.Print("## ", MarkdownEscape(r.Name),
				"\n* **Description**:", r.Description+"\n",
				"\n* **Example**:\n\n```bash\n", r.Example, "\n```\n")
		}
	}
}

// ArgConfig get -config arg value from cli
func ArgConfig() string {
	var configFile string
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-config") {
		if os.Args[1] == "-config" && len(os.Args) > 2 {
			if os.Args[2] == "=" && len(os.Args) > 3 {
				// -config = soar.yaml not support
				fmt.Println("wrong format, no space between '=', eg: -config=soar.yaml")
			} else {
				// -config soar.yaml
				configFile = os.Args[2]
			}
			if strings.HasPrefix(configFile, "=") {
				// -config =soar.yaml
				configFile = strings.Split(configFile, "=")[1]
			}
		}
		if strings.Contains(os.Args[1], "=") {
			// -config=soar.yaml
			configFile = strings.Split(os.Args[1], "=")[1]
		}
	} else {
		for i, c := range os.Args {
			if strings.HasPrefix(c, "-config") && i != 1 {
				fmt.Println("-config must be the first arg")
			}
		}
	}
	return configFile
}
