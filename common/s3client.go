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

func (c *S3Client) FPutObject(objectName, filePath string) (err error) {
	if client, err := c.getClient(); err == nil {
		_, err = client.FPutObject(
			context.Background(),
			Conf.BucketName,
			Conf.BucketPrefix+objectName,
			filePath,
			minio.PutObjectOptions{},
		)
	}

	return
}

func (c *S3Client) GetObject(objectName string) (*minio.Object, error) {
	if client, err := c.getClient(); err == nil {
		return client.GetObject(
			context.Background(),
			Conf.BucketName,
			Conf.BucketPrefix+objectName,
			minio.GetObjectOptions{},
		)
	} else {

		return nil, err
	}
}
