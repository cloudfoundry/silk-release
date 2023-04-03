package client

import (
	"io"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/client/connection"
)

type container struct {
	handle string

	connection connection.Connection
}

func newContainer(handle string, connection connection.Connection) garden.Container {
	return &container{
		handle: handle,

		connection: connection,
	}
}

func (container *container) Handle() string {
	return container.handle
}

func (container *container) Stop(kill bool) error {
	return container.connection.Stop(container.handle, kill)
}

func (container *container) Info() (garden.ContainerInfo, error) {
	return container.connection.Info(container.handle)
}

func (container *container) StreamIn(spec garden.StreamInSpec) error {
	return container.connection.StreamIn(container.handle, spec)
}

func (container *container) StreamOut(spec garden.StreamOutSpec) (io.ReadCloser, error) {
	return container.connection.StreamOut(container.handle, spec)
}

func (container *container) CurrentBandwidthLimits() (garden.BandwidthLimits, error) {
	return container.connection.CurrentBandwidthLimits(container.handle)
}

func (container *container) CurrentCPULimits() (garden.CPULimits, error) {
	return container.connection.CurrentCPULimits(container.handle)
}

func (container *container) CurrentDiskLimits() (garden.DiskLimits, error) {
	return container.connection.CurrentDiskLimits(container.handle)
}

func (container *container) CurrentMemoryLimits() (garden.MemoryLimits, error) {
	return container.connection.CurrentMemoryLimits(container.handle)
}

func (container *container) Run(spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
	return container.connection.Run(container.handle, spec, io)
}

func (container *container) Attach(processID string, io garden.ProcessIO) (garden.Process, error) {
	return container.connection.Attach(container.handle, processID, io)
}

func (container *container) NetIn(hostPort, containerPort uint32) (uint32, uint32, error) {
	return container.connection.NetIn(container.handle, hostPort, containerPort)
}

func (container *container) NetOut(netOutRule garden.NetOutRule) error {
	return container.connection.NetOut(container.handle, netOutRule)
}

func (container *container) BulkNetOut(netOutRules []garden.NetOutRule) error {
	return container.connection.BulkNetOut(container.handle, netOutRules)
}

func (container *container) Metrics() (garden.Metrics, error) {
	return container.connection.Metrics(container.handle)
}

func (container *container) SetGraceTime(graceTime time.Duration) error {
	return container.connection.SetGraceTime(container.handle, graceTime)
}

func (container *container) Properties() (garden.Properties, error) {
	return container.connection.Properties(container.handle)
}

func (container *container) Property(name string) (string, error) {
	return container.connection.Property(container.handle, name)
}

func (container *container) SetProperty(name string, value string) error {
	return container.connection.SetProperty(container.handle, name, value)
}

func (container *container) RemoveProperty(name string) error {
	return container.connection.RemoveProperty(container.handle, name)
}
