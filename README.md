# prsdm-fanotify
TBD
# Example main.go
```
package main

import (
  "os"
  "os/signal"
  "strings"

  "github.com/gianniszach/prsdm-fanotify"
)

func main() {
	fileChangeChan := make(chan prsdmfanotify.FileChange, 100)
	go prsdmfanotify.Listen("/root/work/giannis/fswatch-test/", isFiltered, fileChangeChan)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		break
	}
}

func isFiltered(path string) bool {
  if strings.HasPrefix(path, "/var") {
    return true
  }
  if strings.HasPrefix(path, "/tmp") {
    return true
  }
  if strings.HasPrefix(path, "/root/work/giannis/") {
    return false
  }
  return true
}
```
