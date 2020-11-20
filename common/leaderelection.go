package common

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func LeaderElectionRunOrDie(leaseName string) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		klog.Error(err)
		return
	}

	client := kubernetes.NewForConfigOrDie(cfg)
	if client == nil {
		klog.Error("k8s client init fail")
		return
	}

	run := func(ctx context.Context) {
		select {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan os.Signal, 1)

	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-ch
		klog.Info("Received termination, signaling shutdown")
		cancel()
	}()

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: Namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: Hostname,
		},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				run(ctx)
			},
			OnStoppedLeading: func() {
				klog.Infof("leader lost: %s", Hostname)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				if IsLeader = identity == Hostname; IsLeader {
					return
				}
				klog.Infof("new leader elected: %s", identity)
			},
		},
	})
}
