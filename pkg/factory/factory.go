package factory

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/free5gc/n3iwue/internal/logger"
)

var (
	N3ueConfig Config
	N3ueInfo   N3UEInfo
	N3iwfInfo  N3IWFInfo
)
var filePath string

func InitConfigFactory(f string) error {
	filePath = f
	if content, err := os.ReadFile(filePath); err != nil {
		return err
	} else {
		N3ueConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &N3ueConfig); yamlErr != nil {
			return yamlErr
		}
		N3ueInfo = N3ueConfig.Configuration.N3UEInfo
		N3iwfInfo = N3ueConfig.Configuration.N3IWFInfo

		if err := checkConfigVersion(); err != nil {
			logger.CfgLog.Errorf("Init Config Fail: %+v", err)
		}

		N3ueConfig.SetLogLevel()
	}

	return nil
}

func WriteConfigWithKey(key, value string) error {
	var (
		data []byte
		err  error
		root yaml.Node
	)

	if data, err = os.ReadFile(filePath); err != nil {
		return err
	}

	if err = yaml.Unmarshal(data, &root); err != nil {
		return err
	}

	if ptr := findNodePtrWithKey(&root, key); ptr != nil {
		ptr.Value = value
	} else {
		return errors.New("There's no value with the key")
	}

	if data, err = yaml.Marshal(&root); err != nil {
		return err
	}

	if err = os.WriteFile(filePath, data, 0); err != nil {
		return err
	}

	return nil
}

// Trace yaml node tree with DFS and return the pointer of node with the key
func findNodePtrWithKey(node *yaml.Node, key string) *yaml.Node {
	for i := range node.Content {
		if node.Content[i].Value == key {
			// A pair of key and value are located at same Content *[]yaml.Node
			return node.Content[i+1]
		}
		if ptr := findNodePtrWithKey(node.Content[i], key); ptr != nil {
			return ptr
		}
	}
	return nil
}

func checkConfigVersion() error {
	currentVersion := N3ueConfig.GetVersion()

	if currentVersion != N3ueExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, N3ueExpectedConfigVersion)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}

func SyncConfigSQN(offset uint8) error {
	if sqn, err := strconv.ParseInt(N3ueInfo.Security.SQN, 16, 0); err == nil {
		sqn = sqn + int64(offset)
		logger.CfgLog.Infof("Write SQN=%12x into config file", sqn)
		if err = WriteConfigWithKey("SQN", fmt.Sprintf("%12x", sqn)); err != nil {
			return fmt.Errorf("Write config file: %+v", err)
		}
	} else {
		return fmt.Errorf("Parse SQN fail: %+v", err)
	}

	return nil
}
