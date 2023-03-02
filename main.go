package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	flag.Parse()

	if *clientId == "" || *clientSecret == "" {
		log.Println("need --client-id and --client-secret, or ")
		log.Println("  set environment variables FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
		os.Exit(1)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
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
