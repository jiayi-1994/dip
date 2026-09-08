package main

import (
	"flag"
	"os"
	"slices"
	"testing"
)

func TestMirrorConfiguration(t *testing.T) {
	tests := []struct {
		name string
		env  string
		args []string
		want []string
	}{
		{name: "direct by default"},
		{name: "environment opt in", env: "mirror.example.com", want: []string{"mirror.example.com"}},
		{name: "explicit mirrors", args: []string{"-m", "one.example.com,two.example.com"}, want: []string{"one.example.com", "two.example.com"}},
		{name: "flag overrides environment", env: "env.example.com", args: []string{"-m=cli.example.com"}, want: []string{"cli.example.com"}},
		{name: "empty flag disables environment", env: "env.example.com", args: []string{"-m="}},
		{name: "empty argument disables environment", env: "env.example.com", args: []string{"-m", ""}},
		{name: "ignore blank flag entries", env: "env.example.com", args: []string{"-m", " , one.example.com, ,two.example.com, "}, want: []string{"one.example.com", "two.example.com"}},
		{name: "ignore blank environment entries", env: " , one.example.com, , ", want: []string{"one.example.com"}},
		{name: "blank list disables environment", env: "env.example.com", args: []string{"-m", " , "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DOCKER_PULL_MIRRORS", tt.env)
			oldArgs, oldFlags := os.Args, flag.CommandLine
			t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
			os.Args = append([]string{"dip", "-i", "ghcr.io/jiayi-1994/ai-flowchart:sha-0520fbb"}, tt.args...)
			flag.CommandLine = flag.NewFlagSet("dip", flag.ContinueOnError)
			config := parseFlags()
			if !slices.Equal(config.Mirrors, tt.want) {
				t.Fatalf("mirrors = %v, want %v", config.Mirrors, tt.want)
			}
			registry, _, _ := parseImageName(config.Image, config.Registry)
			config.Registry = registry
			var attempted []string
			_, err := tryRegistries(config, func(host string) (any, error) {
				attempted = append(attempted, host)
				return "ok", nil
			})
			wantHost := "ghcr.io"
			if len(tt.want) > 0 {
				wantHost = tt.want[0]
			}
			if err != nil || !slices.Equal(attempted, []string{wantHost}) {
				t.Fatalf("attempted = %v, err = %v, want only %s", attempted, err, wantHost)
			}
		})
	}
}
