package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
	"sync"
	"time"

	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/client"
	"code.cloudfoundry.org/garden/client/connection"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagerflags"
	"code.cloudfoundry.org/lib/common"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/serial"
)

var (
	interval      *int
	gardenNetwork *string
	gardenAddr    *string
	silkFile      *string
	silkFileOwner *string
	silkFileGroup *string
	logLevel      *string
)

func init() {
	interval = flag.Int("n", 30, "sync interval in seconds.")
	gardenNetwork = flag.String("gardenNetwork", "", "garden network type.")
	gardenAddr = flag.String("gardenAddr", "", "garden address.")
	silkFile = flag.String("silkFile", "", "silk file.")
	silkFileOwner = flag.String("silkFileOwner", "", "owner of silk file")
	silkFileGroup = flag.String("silkFileGroup", "", "group owner of silk file")
	logLevel = flag.String("logLevel", lager.INFO.String(), "log level")
}

func main() {
	flag.Parse()
	loggerConfig := common.GetLagerConfig()
	loggerConfig.LogLevel = *logLevel
	logger, _ := lagerflags.NewFromConfig(fmt.Sprintf("%s.%s", "cfnetworking", "silk-datastore-syncer"), loggerConfig)

	logger.Info("properties", lager.Data{
		"interval":      interval,
		"gardenNetwork": gardenNetwork,
		"gardenAddr":    gardenAddr,
		"silkFile":      silkFile,
		"silkFileOwner": *silkFileOwner,
		"silkFileGroup": *silkFileGroup,
	})

	gardenClient := client.New(connection.New(*gardenNetwork, *gardenAddr))
	WaitForGarden(gardenClient, logger)
	store := makeDatastore()

	duration := time.Duration(*interval) * time.Second
	for {
		time.Sleep(duration)
		logger.Debug("Starting sync loop")

		gardenContainers, err := gardenClient.Containers(nil)
		if err != nil {
			logger.Error("Garden: error retrieving containers:", err)
			continue
		}

		storeContainers, err := store.ReadAll()
		if err != nil {
			logger.Error("Datastore: error retrieving containers from datastore:", err)
			continue
		}

		for _, c := range gardenContainers {
			desiredLogConfig, err := getGardenLogConfig(c)
			if err != nil {
				logger.Error("error getting garden log config", err)
				continue
			}
			logger.Debug("Garden container", lager.Data{"log info": desiredLogConfig})

			sc, ok := storeContainers[c.Handle()]
			if !ok {
				logger.Info("skipping-container-not-found-in-networking-store", lager.Data{"garden_container_handle": c.Handle()})
				continue
			}

			actualLogConfig, err := getSilkLogConfig(sc)
			if err != nil {
				logger.Error("error getting silk log config", err)
				continue
			}
			logger.Debug("Datastore container", lager.Data{"log info": actualLogConfig})

			if reflect.DeepEqual(desiredLogConfig, actualLogConfig) {
				logger.Debug("They are equal no action taken")
				continue
			}

			logger.Debug("Datastore container reconciling with Garden container", lager.Data{"handle": sc.Handle})
			b, err := json.Marshal(desiredLogConfig)
			if err != nil {
				logger.Error("Garden container error marshalling container log config", err, lager.Data{"handle": sc.Handle})
				continue
			}
			if sc.Metadata == nil {
				sc.Metadata = make(map[string]interface{})
			}
			sc.Metadata["log_config"] = string(b)
			err = store.Update(sc.Handle, sc.IP, sc.Metadata)
			if err != nil {
				logger.Error("Error updating log config", err)
			}
		}
	}
}

func WaitForGarden(gardenClient garden.Client, logger lager.Logger) {
	for {
		logger.Debug("Attempting to ping Garden")
		err := gardenClient.Ping()
		if err == nil {
			break
		}
		switch err.(type) {
		case nil:
			break
		case garden.UnrecoverableError:
			logger.Fatal("Garden: unrecoverable", err)
		default:
			logger.Error("Garden: cannot connect", err)
			time.Sleep(1 * time.Second)
		}
	}

}
func makeDatastore() *datastore.Store {
	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker: &filelock.Locker{
			FileLocker: filelock.NewLocker(*silkFile + "_lock"),
			Mutex:      new(sync.Mutex),
		},
		DataFilePath:    *silkFile,
		VersionFilePath: *silkFile + "_version",
		LockedFilePath:  *silkFile + "_lock",
		FileOwner:       *silkFileOwner,
		FileGroup:       *silkFileGroup,
		CacheMutex:      new(sync.RWMutex),
	}
	return store
}

func getGardenLogConfig(c garden.Container) (executor.LogConfig, error) {
	props, err := c.Properties()
	if err != nil {
		err = fmt.Errorf("Garden container: %s: error retrieving properties: %w", c.Handle(), err)
		return executor.LogConfig{}, err
	}
	logConfigStr, ok := props["log_config"]
	var desiredLogConfig executor.LogConfig
	if ok {
		err := json.Unmarshal([]byte(logConfigStr), &desiredLogConfig)
		if err != nil {
			err = fmt.Errorf("Garden container: %s unmarshalling container log config from datastore: %w", c.Handle(), err)
			return executor.LogConfig{}, err
		}
	}
	return desiredLogConfig, nil
}

func getSilkLogConfig(sc datastore.Container) (executor.LogConfig, error) {
	var actualLogConfig executor.LogConfig
	logConfigStr, ok := sc.Metadata["log_config"].(string)
	if ok {
		err := json.Unmarshal([]byte(logConfigStr), &actualLogConfig)
		if err != nil {
			err = fmt.Errorf("Datastore container: %s: error unmarshalling container log config from datastore: %w", sc.Handle, err)
			return executor.LogConfig{}, err
		}
	}
	return actualLogConfig, nil
}
