package common

import (
	"context"
	"github.com/caarlos0/env/v6"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"strconv"
)

type S3Client struct {
	CustomConfig
}

func (c *S3Client) getClient() (*minio.Client, error) {
	c.once.Do(func() {
		if err := env.Parse(c); err != nil {
			return
		}
	})

	return minio.New(c.Endpoint+":"+strconv.Itoa(c.Port), &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKeyID, c.SecretAccessKey, ""),
		Secure: c.UseSSL,
	})
}

func (c *S3Client) FPutObject(ch chan int, objectName, filePath string) {
	if client, err := c.getClient(); err == nil {
		if _, err := client.FPutObject(context.Background(),
			c.BucketName,
			c.BucketPrefix+objectName,
			filePath,
			minio.PutObjectOptions{},
		); err == nil {
			ch <- 0
			return
		}
	}

	ch <- 1
}

func (c *S3Client) GetObject(objectName string) (*minio.Object, error) {
	client, err := c.getClient()
	if err != nil {
		return nil, err
	}

	return client.GetObject(context.Background(), c.BucketName, c.BucketPrefix+objectName, minio.GetObjectOptions{})
}
