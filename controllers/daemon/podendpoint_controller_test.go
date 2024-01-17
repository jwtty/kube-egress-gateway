// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	egressgatewayv1alpha1 "github.com/Azure/kube-egress-gateway/api/v1alpha1"
	"github.com/Azure/kube-egress-gateway/pkg/consts"
	"github.com/Azure/kube-egress-gateway/pkg/imds"
	"github.com/Azure/kube-egress-gateway/pkg/netlinkwrapper/mocknetlinkwrapper"
	"github.com/Azure/kube-egress-gateway/pkg/utils/to"
	"github.com/Azure/kube-egress-gateway/pkg/wgctrlwrapper/mockwgctrlwrapper"
)

const (
	pubK2        = "xUgp0rzI2lqa78w9vRTfCTx8UQzZacu4WXXKw86Oy0c="
	privK2       = "OGDxE0+PqdflLqQxdlHigfC7ZKtEh2VMxIElq4RpZWc="
	podIPAddrNet = "10.0.0.25/32"
)

var _ = Describe("Daemon PodEndpoint controller unit tests", func() {
	var (
		r            *PodEndpointReconciler
		req          reconcile.Request
		res          reconcile.Result
		reconcileErr error
		podEndpoint  *egressgatewayv1alpha1.PodEndpoint
		gwConfig     *egressgatewayv1alpha1.StaticGatewayConfiguration
		mclient      *mockwgctrlwrapper.MockClient
		node         = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testNodeName}}
	)

	getTestReconciler := func(objects ...runtime.Object) {
		mctrl := gomock.NewController(GinkgoT())
		cl := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithRuntimeObjects(objects...).Build()
		r = &PodEndpointReconciler{Client: cl}
		r.Netlink = mocknetlinkwrapper.NewMockInterface(mctrl)
		r.WgCtrl = mockwgctrlwrapper.NewMockInterface(mctrl)
		mclient = mockwgctrlwrapper.NewMockClient(mctrl)
	}

	getTestPodEndpoint := func() *egressgatewayv1alpha1.PodEndpoint {
		return &egressgatewayv1alpha1.PodEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testName,
				Namespace: testNamespace,
			},
			Spec: egressgatewayv1alpha1.PodEndpointSpec{
				StaticGatewayConfiguration: testName,
				PodIpAddress:               podIPAddrNet,
				PodPublicKey:               pubK,
			},
		}
	}

	getTestGwConfig := func() *egressgatewayv1alpha1.StaticGatewayConfiguration {
		return &egressgatewayv1alpha1.StaticGatewayConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testName,
				Namespace: testNamespace,
				UID:       testUID,
			},
			Spec: egressgatewayv1alpha1.StaticGatewayConfigurationSpec{
				GatewayVmssProfile: egressgatewayv1alpha1.GatewayVmssProfile{
					VmssResourceGroup:  vmssRG,
					VmssName:           vmssName,
					PublicIpPrefixSize: 31,
				},
			},
			Status: getTestGwConfigStatus(),
		}
	}

	Context("Skip reconcile", func() {
		BeforeEach(func() {
			req = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testName,
					Namespace: testNamespace,
				},
			}
			podEndpoint = getTestPodEndpoint()
			gwConfig = getTestGwConfig()
			nodeMeta = &imds.InstanceMetadata{
				Compute: &imds.ComputeMetadata{
					VMScaleSetName:    vmssName,
					ResourceGroupName: vmssRG,
				},
			}
		})

		When("gwConfig is not found", func() {
			It("should report error", func() {
				getTestReconciler(podEndpoint)
				res, reconcileErr = r.Reconcile(context.TODO(), req)

				Expect(apierrors.IsNotFound(reconcileErr)).To(BeTrue())
				Expect(res).To(Equal(ctrl.Result{}))
			})
		})

		When("gwConfig does not apply to the node", func() {
			It("should not do anything", func() {
				nodeMeta.Compute.VMScaleSetName = vmssName + "a"
				getTestReconciler(podEndpoint, gwConfig)
				res, reconcileErr = r.Reconcile(context.TODO(), req)

				Expect(reconcileErr).To(BeNil())
				Expect(res).To(Equal(ctrl.Result{}))
			})
		})

		When("gwConfig is being deleted", func() {
			It("should report error", func() {
				gwConfig.DeletionTimestamp = to.Ptr(metav1.Now())
				gwConfig.Finalizers = []string{consts.SGCFinalizerName}
				getTestReconciler(podEndpoint, gwConfig)
				res, reconcileErr = r.Reconcile(context.TODO(), req)

				Expect(reconcileErr).To(HaveOccurred())
				Expect(res).To(Equal(ctrl.Result{}))
			})
		})
	})

	Context("Test reconcile", func() {
		BeforeEach(func() {
			req = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testName,
					Namespace: testNamespace,
				},
			}
			podEndpoint = getTestPodEndpoint()
			gwConfig = getTestGwConfig()
			nodeMeta = &imds.InstanceMetadata{
				Compute: &imds.ComputeMetadata{
					VMScaleSetName:    vmssName,
					ResourceGroupName: vmssRG,
				},
			}
			os.Setenv(consts.PodNamespaceEnvKey, testPodNamespace)
			os.Setenv(consts.NodeNameEnvKey, testNodeName)
			getTestReconciler(podEndpoint, gwConfig, node)
		})

		AfterEach(func() {
			os.Setenv(consts.PodNamespaceEnvKey, "")
			os.Setenv(consts.NodeNameEnvKey, "")
		})

		It("should report error when failed to create wgCtrl client", func() {
			mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
			gomock.InOrder(
				mwg.EXPECT().New().Return(nil, fmt.Errorf("failed")),
			)
			_, reconcileErr = r.Reconcile(context.TODO(), req)
			Expect(errors.Unwrap(reconcileErr)).To(Equal(fmt.Errorf("failed")))
		})

		It("should report error when failed to configure wireguard device", func() {
			mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
			pk, _ := wgtypes.ParseKey(pubK)
			config := wgtypes.Config{
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         pk,
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							*getIPNet(podIPAddrNet),
						},
					},
				},
			}
			gomock.InOrder(
				mwg.EXPECT().New().Return(mclient, nil),
				mclient.EXPECT().ConfigureDevice("wg6000", config).Return(fmt.Errorf("failed")),
				mclient.EXPECT().Close().Return(nil),
			)
			_, reconcileErr = r.Reconcile(context.TODO(), req)
			Expect(errors.Unwrap(reconcileErr)).To(Equal(fmt.Errorf("failed")))
		})

		Context("test adding peer route", func() {
			BeforeEach(func() {
				mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
				pk, _ := wgtypes.ParseKey(pubK)
				config := wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						{
							PublicKey:         pk,
							ReplaceAllowedIPs: true,
							AllowedIPs: []net.IPNet{
								*getIPNet(podIPAddrNet),
							},
						},
					},
				}
				gomock.InOrder(
					mwg.EXPECT().New().Return(mclient, nil),
					mclient.EXPECT().ConfigureDevice("wg6000", config).Return(nil),
					mclient.EXPECT().Close().Return(nil),
				)
			})

			It("should report error if failed to get wireguard link", func() {
				mnl := r.Netlink.(*mocknetlinkwrapper.MockInterface)
				wg0 := &netlink.Wireguard{}
				mnl.EXPECT().LinkByName("wg6000").Return(wg0, fmt.Errorf("failed"))
				_, reconcileErr = r.Reconcile(context.TODO(), req)
				Expect(errors.Unwrap(errors.Unwrap(reconcileErr))).To(Equal(fmt.Errorf("failed")))
			})

			It("should report error if failed to add route", func() {
				mnl := r.Netlink.(*mocknetlinkwrapper.MockInterface)
				wg0 := &netlink.Wireguard{}
				gomock.InOrder(
					mnl.EXPECT().LinkByName("wg6000").Return(wg0, nil),
					mnl.EXPECT().RouteReplace(&netlink.Route{LinkIndex: 0, Scope: netlink.SCOPE_LINK, Dst: getIPNet(podIPAddrNet), Table: 0x8000}).Return(fmt.Errorf("failed")),
				)
				_, reconcileErr = r.Reconcile(context.TODO(), req)
				Expect(errors.Unwrap(errors.Unwrap(reconcileErr))).To(Equal(fmt.Errorf("failed")))
			})

			It("should succeed and update gateway status", func() {
				mnl := r.Netlink.(*mocknetlinkwrapper.MockInterface)
				wg0 := &netlink.Wireguard{}
				gomock.InOrder(
					mnl.EXPECT().LinkByName("wg6000").Return(wg0, nil),
					mnl.EXPECT().RouteReplace(&netlink.Route{LinkIndex: 0, Scope: netlink.SCOPE_LINK, Dst: getIPNet(podIPAddrNet), Table: 0x8000}).Return(nil),
				)
				_, reconcileErr = r.Reconcile(context.TODO(), req)
				Expect(reconcileErr).To(BeNil())
				gwStatus := &egressgatewayv1alpha1.GatewayStatus{}
				err := getGatewayStatus(r.Client, gwStatus)
				Expect(err).To(BeNil())
				Expect(gwStatus.Spec.ReadyPeerConfigurations).To(Equal([]egressgatewayv1alpha1.PeerConfiguration{
					{
						PublicKey:     pubK,
						InterfaceName: "wg6000",
						PodEndpoint:   fmt.Sprintf("%s/%s", testNamespace, testName),
					},
				}))
			})
		})
	})

	Context("Test updating gateway node status", func() {
		peerConfigs := []egressgatewayv1alpha1.PeerConfiguration{
			{
				PublicKey:     "pubk1",
				InterfaceName: "wg1",
			},
			{
				PublicKey:     "pubk2",
				InterfaceName: "wg2",
			},
		}

		BeforeEach(func() {
			os.Setenv(consts.PodNamespaceEnvKey, testPodNamespace)
			os.Setenv(consts.NodeNameEnvKey, testNodeName)
		})

		AfterEach(func() {
			os.Setenv(consts.PodNamespaceEnvKey, "")
			os.Setenv(consts.NodeNameEnvKey, "")
		})

		It("should create new gateway status object if not exist", func() {
			getTestReconciler(node)
			err := r.updateGatewayNodeStatus(context.TODO(), peerConfigs, true)
			Expect(err).To(BeNil())
			gwStatus := &egressgatewayv1alpha1.GatewayStatus{}
			err = getGatewayStatus(r.Client, gwStatus)
			Expect(err).To(BeNil())
			Expect(gwStatus.Spec.ReadyPeerConfigurations).To(Equal(peerConfigs))
		})

		It("should update existing gateway status object", func() {
			existing := &egressgatewayv1alpha1.GatewayStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testNodeName,
					Namespace: testPodNamespace,
				},
				Spec: egressgatewayv1alpha1.GatewayStatusSpec{
					ReadyPeerConfigurations: []egressgatewayv1alpha1.PeerConfiguration{
						{
							PublicKey:     "pubk1",
							InterfaceName: "wg1",
						},
						{
							PublicKey:     "pubk3",
							InterfaceName: "wg3",
						},
					},
				},
			}
			getTestReconciler(node, existing)
			err := r.updateGatewayNodeStatus(context.TODO(), peerConfigs, true)
			Expect(err).To(BeNil())
			gwStatus := &egressgatewayv1alpha1.GatewayStatus{}
			err = getGatewayStatus(r.Client, gwStatus)
			Expect(err).To(BeNil())
			var keys []string
			for _, peer := range gwStatus.Spec.ReadyPeerConfigurations {
				keys = append(keys, peer.PublicKey)
			}
			sort.Strings(keys)
			Expect(keys).To(Equal([]string{"pubk1", "pubk2", "pubk3"}))
		})

		It("should update existing gateway status object - deletion", func() {
			existing := &egressgatewayv1alpha1.GatewayStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testNodeName,
					Namespace: testPodNamespace,
				},
				Spec: egressgatewayv1alpha1.GatewayStatusSpec{
					ReadyPeerConfigurations: []egressgatewayv1alpha1.PeerConfiguration{
						{
							PublicKey:     "pubk1",
							InterfaceName: "wg1",
						},
						{
							PublicKey:     "pubk3",
							InterfaceName: "wg3",
						},
					},
				},
			}
			getTestReconciler(node, existing)
			err := r.updateGatewayNodeStatus(context.TODO(), peerConfigs, false)
			Expect(err).To(BeNil())
			gwStatus := &egressgatewayv1alpha1.GatewayStatus{}
			err = getGatewayStatus(r.Client, gwStatus)
			Expect(err).To(BeNil())
			Expect(len(gwStatus.Spec.ReadyPeerConfigurations)).To(Equal(1))
			Expect(gwStatus.Spec.ReadyPeerConfigurations[0].PublicKey).To(Equal("pubk3"))
		})
	})

	Context("Test reconcile peerConfig cleanup", func() {
		BeforeEach(func() {
			req = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "",
					Namespace: "",
				},
			}
			nodeMeta = &imds.InstanceMetadata{
				Compute: &imds.ComputeMetadata{
					VMScaleSetName:    vmssName,
					ResourceGroupName: vmssRG,
				},
			}

			os.Setenv(consts.PodNamespaceEnvKey, testPodNamespace)
			os.Setenv(consts.NodeNameEnvKey, testNodeName)
		})

		AfterEach(func() {
			os.Setenv(consts.PodNamespaceEnvKey, "")
			os.Setenv(consts.NodeNameEnvKey, "")
		})

		It("should clean deleted peer and route", func() {
			gwStatus := &egressgatewayv1alpha1.GatewayStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testNodeName,
					Namespace: testPodNamespace,
				},
				Spec: egressgatewayv1alpha1.GatewayStatusSpec{
					ReadyPeerConfigurations: []egressgatewayv1alpha1.PeerConfiguration{
						{
							PublicKey:     pubK,
							InterfaceName: "wg1",
						},
					},
				},
			}
			gwConfig = getTestGwConfig()
			getTestReconciler(gwConfig, gwStatus)
			mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
			mnl := r.Netlink.(*mocknetlinkwrapper.MockInterface)
			wg0 := &netlink.Wireguard{}
			pk, _ := wgtypes.ParseKey(pubK)
			device := &wgtypes.Device{
				Peers: []wgtypes.Peer{
					{
						PublicKey: pk,
						AllowedIPs: []net.IPNet{
							*getIPNet("10.0.0.1/32"),
							*getIPNet("10.0.0.2/32"),
						},
					},
				},
			}
			config := wgtypes.Config{
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey: pk,
						Remove:    true,
					},
				},
			}
			gomock.InOrder(
				mwg.EXPECT().New().Return(mclient, nil),
				mclient.EXPECT().Device("wg6000").Return(device, nil),
				mnl.EXPECT().LinkByName("wg6000").Return(wg0, nil),
				mnl.EXPECT().RouteDel(&netlink.Route{LinkIndex: 0, Scope: netlink.SCOPE_LINK, Dst: getIPNet("10.0.0.1/32"), Table: 0x8000}).Return(nil),
				mnl.EXPECT().RouteDel(&netlink.Route{LinkIndex: 0, Scope: netlink.SCOPE_LINK, Dst: getIPNet("10.0.0.2/32"), Table: 0x8000}).Return(nil),
				mclient.EXPECT().ConfigureDevice("wg6000", config).Return(nil),
				mclient.EXPECT().Close().Return(nil),
			)
			_, reconcileErr = r.Reconcile(context.TODO(), req)
			Expect(reconcileErr).To(BeNil())
			err := getGatewayStatus(r.Client, gwStatus)
			Expect(err).To(BeNil())
			Expect(gwStatus.Spec.ReadyPeerConfigurations).To(BeEmpty())
		})

		It("should not clean existing peer and route", func() {
			podEndpoint = getTestPodEndpoint()
			podEndpoint.Name = testName + "a"
			gwConfig = getTestGwConfig()
			getTestReconciler(podEndpoint, gwConfig)
			mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
			pk, _ := wgtypes.ParseKey(pubK)
			device := &wgtypes.Device{
				Peers: []wgtypes.Peer{
					{
						PublicKey: pk,
						AllowedIPs: []net.IPNet{
							*getIPNet("10.0.0.1/32"),
						},
					},
				},
			}
			gomock.InOrder(
				mwg.EXPECT().New().Return(mclient, nil),
				mclient.EXPECT().Device("wg6000").Return(device, nil),
				mclient.EXPECT().Close().Return(nil),
			)
			_, reconcileErr = r.Reconcile(context.TODO(), req)
			Expect(reconcileErr).To(BeNil())
		})

		It("should handle multiple gateway configurations properly", func() {
			objects := []runtime.Object{
				getTestGwConfig(),
				&egressgatewayv1alpha1.StaticGatewayConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testName + "a",
						Namespace: testNamespace,
						UID:       "1234567891",
					},
					Spec: egressgatewayv1alpha1.StaticGatewayConfigurationSpec{
						GatewayVmssProfile: egressgatewayv1alpha1.GatewayVmssProfile{
							VmssResourceGroup:  vmssRG,
							VmssName:           vmssName,
							PublicIpPrefixSize: 31,
						},
					},
					Status: egressgatewayv1alpha1.StaticGatewayConfigurationStatus{
						EgressIpPrefix: "1.2.3.4/31",
						GatewayServerProfile: egressgatewayv1alpha1.GatewayServerProfile{
							Ip:        ilbIP,
							Port:      6001,
							PublicKey: pubK,
							PrivateKeySecretRef: &corev1.ObjectReference{
								APIVersion: "v1",
								Kind:       "Secret",
								Name:       testName,
								Namespace:  testSecretNamespace,
							},
						},
					},
				},
				&egressgatewayv1alpha1.PodEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testName + "a",
						Namespace: testNamespace,
					},
					Spec: egressgatewayv1alpha1.PodEndpointSpec{
						StaticGatewayConfiguration: testName,
						PodIpAddress:               "10.0.0.1",
						PodPublicKey:               pubK,
					},
				},
			}
			getTestReconciler(objects...)
			mwg := r.WgCtrl.(*mockwgctrlwrapper.MockInterface)
			mnl := r.Netlink.(*mocknetlinkwrapper.MockInterface)
			wg0 := &netlink.Wireguard{}
			pk, _ := wgtypes.ParseKey(pubK)
			pk2, _ := wgtypes.ParseKey(pubK2)
			device := &wgtypes.Device{
				Peers: []wgtypes.Peer{
					{
						PublicKey: pk,
						AllowedIPs: []net.IPNet{
							*getIPNet("10.0.0.1/32"),
						},
					},
					{
						PublicKey: pk2,
						AllowedIPs: []net.IPNet{
							*getIPNet("10.0.0.2/32"),
						},
					},
				},
			}
			config := wgtypes.Config{
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey: pk2,
						Remove:    true,
					},
				},
			}
			// 1st gateway config, delete one peer and keey one peer
			mwg.EXPECT().New().Return(mclient, nil)
			mclient.EXPECT().Device("wg6000").Return(device, nil)
			mnl.EXPECT().LinkByName("wg6000").Return(wg0, nil)
			mnl.EXPECT().RouteDel(&netlink.Route{LinkIndex: 0, Scope: netlink.SCOPE_LINK, Dst: getIPNet("10.0.0.2/32"), Table: 0x8000}).Return(nil)
			mclient.EXPECT().ConfigureDevice("wg6000", config).Return(nil)
			mclient.EXPECT().Close().Return(nil)
			// 2nd gateway config, return error, should not block
			mclient.EXPECT().Device("wg6001").Return(nil, fmt.Errorf("failed"))
			_, reconcileErr = r.Reconcile(context.TODO(), req)
			Expect(reconcileErr).To(BeNil())
		})
	})
})

func getGatewayStatus(cl client.Client, gwStatus *egressgatewayv1alpha1.GatewayStatus) error {
	key := types.NamespacedName{
		Name:      testNodeName,
		Namespace: testPodNamespace,
	}
	err := cl.Get(context.TODO(), key, gwStatus)
	return err
}
