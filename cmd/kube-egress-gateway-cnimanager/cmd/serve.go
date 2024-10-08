// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	clientretry "k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	current "github.com/Azure/kube-egress-gateway/api/v1alpha1"
	"github.com/Azure/kube-egress-gateway/controllers/cnimanager"
	cniconf "github.com/Azure/kube-egress-gateway/pkg/cni/conf"
	cniprotocol "github.com/Azure/kube-egress-gateway/pkg/cniprotocol/v1"
	"github.com/Azure/kube-egress-gateway/pkg/consts"
	"github.com/Azure/kube-egress-gateway/pkg/logger"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "cni daemon service",
	Long:  `A daemon service that serves cni requests from cni plugin`,
	Run:   ServiceLauncher,
}

var (
	confFileName              string
	exceptionCidrs            string
	cniUninstallConfigMapName string
	grpcPort                  int
)

func init() {
	rootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serveCmd.Flags().IntVar(&grpcPort, "grpc-server-port", 50051, "The port the grpc server listens on.")
	serveCmd.Flags().StringVar(&exceptionCidrs, "exception-cidrs", "", "Cidrs that should bypass egress gateway separated with ',', e.g. intra-cluster traffic")
	serveCmd.Flags().StringVar(&confFileName, "cni-conf-file", "01-egressgateway.conflist", "Name of the new cni configuration file")
	serveCmd.Flags().StringVar(&cniUninstallConfigMapName, "cni-uninstall-configmap-name", "cni-uninstall", "Name of the configmap that indicates whether to uninstall cni plugin or not, the configMap should be in the same namespace as the cniManager pod")
}

func ServiceLauncher(cmd *cobra.Command, args []string) {
	ctx := signals.SetupSignalHandler()
	g, ctx := errgroup.WithContext(ctx)
	zapLog, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	logger.SetDefaultLogger(zapr.NewLogger(zapLog))
	logger := logger.GetLogger()

	k8sCluster := getKubeCluster(ctx, logger)
	k8sClient := k8sCluster.GetClient()

	cniConfMgr, err := cniconf.NewCNIConfManager(consts.CNIConfDir, confFileName, exceptionCidrs, cniUninstallConfigMapName, k8sClient, grpcPort)
	if err != nil {
		logger.Error(err, "failed to create cni config manager")
		os.Exit(1)
	}

	nodeTaintHandler := toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			removeNodeTaintIfNeeded(obj, func() bool { return cniConfMgr.IsReady() }, k8sClient, logger)
		},
		UpdateFunc: func(_, newObj interface{}) {
			removeNodeTaintIfNeeded(newObj, func() bool { return cniConfMgr.IsReady() }, k8sClient, logger)
		},
	}
	startKubeCluster(ctx, k8sCluster, nodeTaintHandler, logger)

	g.Go(func() error {
		if err := cniConfMgr.Start(ctx); err != nil {
			logger.Error(err, "failed to start cni config manager monitoring")
			os.Exit(1)
		}
		return nil
	})

	nicSvc := cnimanager.NewNicService(k8sClient)
	server := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_zap.StreamServerInterceptor(zapLog),
			grpc_prometheus.StreamServerInterceptor,
			grpc_recovery.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_zap.UnaryServerInterceptor(
				zapLog,
				grpc_zap.WithDecider(func(fullMethodName string, err error) bool {
					return fullMethodName != "/grpc.health.v1.Health/Check"
				})),
			grpc_prometheus.UnaryServerInterceptor,
			grpc_recovery.UnaryServerInterceptor(),
		)),
	)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(server, healthServer)

	cniprotocol.RegisterNicServiceServer(server, nicSvc)
	var listener net.Listener
	listener, err = net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		logger.Error(err, "failed to listen")
		os.Exit(1)
	}

	g.Go(func() error {
		<-ctx.Done()
		logger.Error(ctx.Err(), "os signal received, shutting down")
		server.GracefulStop()
		return nil
	})
	err = server.Serve(listener)
	if err != nil {
		logger.Error(err, "failed to serve")
	}
	// wait for all context to be done
	err = g.Wait()
	if err != nil {
		logger.Error(err, "unexpected error returned from errgroup")
	}
	logger.Info("server shutdown")
}

func getKubeCluster(ctx context.Context, logger logr.Logger) cluster.Cluster {
	apischeme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(apischeme))
	utilruntime.Must(current.AddToScheme(apischeme))
	k8sCluster, err := cluster.New(config.GetConfigOrDie(), func(options *cluster.Options) {
		options.Scheme = apischeme
		options.Logger = logger
		options.Cache = cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.ConfigMap{}: {
					// we only watch this specific one cm object
					Field: fields.SelectorFromSet(fields.Set{
						"metadata.name":      cniUninstallConfigMapName,
						"metadata.namespace": os.Getenv(consts.PodNamespaceEnvKey),
					}),
				},
				&corev1.Node{}: {
					// we only watch the node where cniManager pod is running
					Field: fields.OneTermEqualSelector("metadata.name", os.Getenv(consts.NodeNameEnvKey)),
				},
			},
		}
	})
	if err != nil {
		logger.Error(err, "failed to create k8s cluster object")
		os.Exit(1)
	}
	return k8sCluster
}

func startKubeCluster(ctx context.Context, k8sCluster cluster.Cluster, handler toolscache.ResourceEventHandler, logger logr.Logger) {
	nodeInformer, err := k8sCluster.GetCache().GetInformer(ctx, &corev1.Node{})
	if err != nil {
		logger.Error(err, "failed to get node informer")
		os.Exit(1)
	}
	_, err = nodeInformer.AddEventHandler(handler)
	if err != nil {
		logger.Error(err, "failed to add node event handler")
		os.Exit(1)
	}

	go func() {
		if err := k8sCluster.Start(ctx); err != nil {
			logger.Error(err, "failed to start k8s client cache")
			os.Exit(1)
		}
	}()

	// wait for initial cache sync
	k8sCluster.GetCache().WaitForCacheSync(ctx)
	k8sClient := k8sCluster.GetClient()
	cm := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: cniUninstallConfigMapName, Namespace: os.Getenv(consts.PodNamespaceEnvKey)}, cm); err != nil {
		// only get the configMap to trigger informer start, ignore the error
		logger.Error(err, "failed to get cni uninstall configMap, error ignored", "configMap name", cniUninstallConfigMapName)
	}
}

func removeNodeTaintIfNeeded(obj interface{}, isReady func() bool, k8sClient client.Client, logger logr.Logger) {
	node := obj.(*corev1.Node)
	logger.Info("checking node taint", "node", node.Name)
	for i, taint := range node.Spec.Taints {
		if taint.Key == consts.CNIManagerNotReadyTaintKey {
			if isReady() {
				logger.Info("cni configuration file is ready, removing node taint", "node", node.Name)
				// make a deep copy of the node since we should not modify the obj inside ResourceEventHandler
				newNode := node.DeepCopy()
				newNode.Spec.Taints = append(newNode.Spec.Taints[:i], newNode.Spec.Taints[i+1:]...)
				if err := clientretry.RetryOnConflict(clientretry.DefaultRetry, func() error {
					return k8sClient.Update(context.Background(), newNode)
				}); err != nil {
					logger.Error(err, "failed to remove node taint", "node", newNode.Name)
				}
			} else {
				logger.Info("cni configuration file is not ready yet, keeping node taint", "node", node.Name)
			}
			return
		}
	}
}
