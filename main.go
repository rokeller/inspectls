package main

import (
	"github.com/rokeller/inspectls/v2/cmd"
	"k8s.io/klog/v2"
)

func main() {
	cmd.Execute()
	klog.Flush()
}
