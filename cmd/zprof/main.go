package main

import (
	"os"

	"zgo.at/zprof"
)

func main() {
	l := ""
	if len(os.Args) > 1 {
		l = os.Args[1]
	}
	zprof.Profile(l)
	<-make(chan bool)
}
