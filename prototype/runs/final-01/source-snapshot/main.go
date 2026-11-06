package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fatal(fmt.Errorf("usage: wireproof-demo run|replay|summarize|serve"))
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "run":
		f := flag.NewFlagSet("run", flag.ExitOnError)
		out := f.String("out", "runs/demo", "output directory")
		n := f.Int("repetitions", 10, "repetitions per scenario")
		f.Parse(os.Args[2:])
		if *n < 1 {
			fatal(fmt.Errorf("repetitions must be positive"))
		}
		fatalIf(run(*out, *n))
	case "replay", "summarize":
		f := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		dir := f.String("dir", "runs/demo", "run directory")
		f.Parse(os.Args[2:])
		if os.Args[1] == "replay" {
			fatalIf(replay(*dir))
		} else {
			fatalIf(summarize(*dir))
		}
	default:
		fatal(fmt.Errorf("unknown command"))
	}
}
func fatalIf(e error) {
	if e != nil {
		fatal(e)
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
