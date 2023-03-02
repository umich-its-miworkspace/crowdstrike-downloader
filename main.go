package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
)

func main() {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     "",
		ClientSecret: "",
		Debug:        false,
		Context:      context.Background(),
	})

	if err != nil {
		log.Fatal(err)
	}

	// ask for all the client downloads for Mac and Windows
	filter := "(platform:'windows'),(platform:'mac')"
	sensors, err := client.SensorDownload.GetCombinedSensorInstallersByQuery(
		&sensor_download.GetCombinedSensorInstallersByQueryParams{
			Filter:  &filter,
			Context: context.Background(),
		},
	)

	if err != nil {
		log.Fatal(err)
	}

	payload := sensors.GetPayload()

	// loop through each
	for _, sensor := range payload.Resources {
		err := os.MkdirAll(*sensor.Platform, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}

		// construct path
		var extension string

		switch *sensor.Platform {
		case "windows":
			extension = "exe"
		case "mac":
			extension = "pkg"
		}

		preferredPathname := fmt.Sprintf("%s/CrowdStrike-Falcon-%s.%s", *sensor.Platform, *sensor.Version, extension)

		// create file to write into
		file, err := os.OpenFile(preferredPathname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			// exists, loop to next
			if errors.Is(err, syscall.EEXIST) {
				log.Println("Skippping", preferredPathname)
				continue
			} else {
				log.Fatal(err)
			}
		}

		// download
		log.Println("Downloading", preferredPathname)
		_, err = client.SensorDownload.DownloadSensorInstallerByID(
			&sensor_download.DownloadSensorInstallerByIDParams{
				ID:      *sensor.Sha256,
				Context: context.Background(),
			}, file)

		if err != nil {
			log.Fatal(falcon.ErrorExplain(err))
		}
	}
}
