package common

import (
	"context"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"strconv"
)

type S3Client struct{}

func (c *S3Client) getClient() (*minio.Client, error) {
	return minio.New(
		Conf.Endpoint+":"+strconv.Itoa(Conf.Port),
		&minio.Options{
			Creds:  credentials.NewStaticV4(Conf.AccessKeyID, Conf.SecretAccessKey, ""),
			Secure: Conf.UseSSL,
		},
	)
}

func (c *S3Client) FPutObject(ch chan int, objectName, filePath string) {
	if client, err := c.getClient(); err == nil {
		if _, err := client.FPutObject(
			context.Background(),
			Conf.BucketName,
			Conf.BucketPrefix+objectName,
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

	return client.GetObject(
		context.Background(),
		Conf.BucketName,
		Conf.BucketPrefix+objectName,
		minio.GetObjectOptions{},
	)
}
