package systemtests

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

func RunTestsOnDocker() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	apiClient, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating new docker client: %w", err)
	}
	defer apiClient.Close()

	reader, err := apiClient.ImagePull(ctx, "golang:latest", image.PullOptions{})
	if err != nil {
		return fmt.Errorf("error pulling image: %w", err)
	}

	return nil

}
