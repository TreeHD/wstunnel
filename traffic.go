// traffic.go — 流量統計與持久化
//
// 職責：
//   * TrafficInfo 結構
//   * globalTraffic sync.Map 集中存放所有用戶的流量
//   * 啟動時載入歷史紀錄、定期/結束時存盤
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type TrafficInfo struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

var globalTraffic sync.Map

const trafficFileName = "data/traffic.json"

// loadTrafficData 啟動時把 data/traffic.json 讀進 globalTraffic
func loadTrafficData() {
	data, err := ioutil.ReadFile(trafficFileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("System: Traffic data file (%s) not found, starting with empty records.", trafficFileName)
			return
		}
		log.Printf("System: Error reading traffic data file: %v", err)
		return
	}
	var trafficFromFile map[string]*TrafficInfo
	if err := json.Unmarshal(data, &trafficFromFile); err != nil {
		log.Printf("System: Error parsing traffic data file: %v", err)
		return
	}
	for username, trafficInfo := range trafficFromFile {
		globalTraffic.Store(username, &TrafficInfo{
			Sent:     atomic.LoadUint64(&trafficInfo.Sent),
			Received: atomic.LoadUint64(&trafficInfo.Received),
		})
	}
	log.Printf("System: Successfully loaded %d user traffic records from %s", len(trafficFromFile), trafficFileName)
}

// saveTrafficData 把 globalTraffic 序列化寫盤
func saveTrafficData() error {
	trafficToSave := make(map[string]*TrafficInfo)
	globalTraffic.Range(func(key, value interface{}) bool {
		trafficToSave[key.(string)] = value.(*TrafficInfo)
		return true
	})
	data, err := json.MarshalIndent(trafficToSave, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal traffic data: %w", err)
	}
	if err := ioutil.WriteFile(trafficFileName, data, 0644); err != nil {
		return fmt.Errorf("failed to write traffic data to file: %w", err)
	}
	log.Printf("System: Traffic data successfully saved to %s", trafficFileName)
	return nil
}

// startPeriodicTrafficSaver 啟動背景常式定期存盤
func startPeriodicTrafficSaver() {
	saveInterval := time.Duration(globalConfig.TrafficSaveIntervalSeconds) * time.Second
	log.Printf("System: Traffic data will be saved every %v.", saveInterval)
	go func() {
		ticker := time.NewTicker(saveInterval)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := saveTrafficData(); err != nil {
				log.Printf("System: Error during periodic traffic data save: %v", err)
			}
		}
	}()
}
