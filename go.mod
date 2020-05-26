module github.com/smallnest/soar

go 1.14

replace (
	github.com/coreos/bbolt => go.etcd.io/bbolt v1.3.3
	github.com/pingcap/tidb => ./vendor/github.com/pingcap/tidb
)

require (
	github.com/CorgiMan/json2 v0.0.0-20150213135156-e72957aba209
	github.com/astaxie/beego v1.12.1
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/gedex/inflector v0.0.0-20170307190818-16278e9db813
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0 // indirect
	github.com/juju/errors v0.0.0-20200330140219-3fe23663418f // indirect
	github.com/kr/pretty v0.2.0
	github.com/onsi/ginkgo v1.12.2 // indirect
	github.com/percona/go-mysql v0.0.0-20200511222729-cd2547baca36
	github.com/pingcap/parser v3.1.1+incompatible
	github.com/pingcap/tidb v1.1.0-beta.0.20200526032053-17cf2060b636
	github.com/pingcap/tipb v0.0.0-20200522051215-f31a15d98fce // indirect
	github.com/prometheus/client_golang v1.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/russross/blackfriday v1.5.2
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca
	github.com/shiena/ansicolor v0.0.0-20151119151921-a422bbe96644 // indirect
	github.com/shurcooL/httpfs v0.0.0-20190707220628-8d4bc4ba7749 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tidwall/gjson v1.6.0
	github.com/tmc/grpc-websocket-proxy v0.0.0-20200427203606-3cfed13b9966 // indirect
	github.com/uber/jaeger-client-go v2.23.1+incompatible // indirect
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/youtube/vitess v2.1.1+incompatible // indirect
	go.etcd.io/bbolt v1.3.4 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	google.golang.org/grpc v1.29.1 // indirect
	gopkg.in/yaml.v2 v2.3.0
	sigs.k8s.io/yaml v1.2.0 // indirect
	vitess.io/vitess v2.1.1+incompatible
)
