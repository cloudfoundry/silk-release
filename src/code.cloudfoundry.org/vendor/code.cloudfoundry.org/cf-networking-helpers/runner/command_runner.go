package runner

import (
	"io"
	"os"
	"os/exec"
)

type Command struct {
	Args []string
	Dir  string
}

type CommandRunner struct {
	Executable string
	Stdout     io.Writer
	Stderr     io.Writer
}

func NewCommandRunner(executable string, quiet bool) (CommandRunner, error) {
	executablePath, err := exec.LookPath(executable)
	if err != nil {
		return CommandRunner{}, err
	}

	commandRunner := CommandRunner{
		Executable: executablePath,
	}
	if !quiet {
		commandRunner.Stdout = os.Stdout
		commandRunner.Stderr = os.Stderr
	}
	return commandRunner, nil
}

func (r CommandRunner) CombinedOutput(command Command) ([]byte, error) {
	cmd := &exec.Cmd{
		Path: r.Executable,
		Args: append([]string{r.Executable}, command.Args...),
		Dir:  command.Dir,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, err
	}

	return output, nil
}

func (r CommandRunner) Run(command Command) error {
	cmd := &exec.Cmd{
		Path:   r.Executable,
		Args:   append([]string{r.Executable}, command.Args...),
		Dir:    command.Dir,
		Stdout: r.Stdout,
		Stderr: r.Stderr,
	}

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
