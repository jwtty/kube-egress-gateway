// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	egressgatewayv1alpha1 "github.com/Azure/kube-egress-gateway/api/v1alpha1"
	"github.com/Azure/kube-egress-gateway/pkg/azmanager"
	"github.com/Azure/kube-egress-gateway/pkg/consts"
	"github.com/Azure/kube-egress-gateway/pkg/healthprobe"
	"github.com/Azure/kube-egress-gateway/pkg/imds"
	"github.com/Azure/kube-egress-gateway/pkg/netlinkwrapper"
	"github.com/Azure/kube-egress-gateway/pkg/utils/to"
	"github.com/Azure/kube-egress-gateway/pkg/wgctrlwrapper"
)

var _ reconcile.Reconciler = &StaticGatewayConfigurationReconciler{}

// StaticGatewayConfigurationReconciler reconciles gateway node network according to a StaticGatewayConfiguration object
type StaticGatewayConfigurationReconciler struct {
	client.Client
	*azmanager.AzureManager
	TickerEvents  chan event.GenericEvent
	LBProbeServer *healthprobe.LBProbeServer
	Netlink       netlinkwrapper.Interface
	IPTables      utiliptables.Interface
	WgCtrl        wgctrlwrapper.Interface
}

//+kubebuilder:rbac:groups=egressgateway.kubernetes.azure.com,resources=staticgatewayconfigurations,verbs=get;list;watch
//+kubebuilder:rbac:groups=egressgateway.kubernetes.azure.com,resources=staticgatewayconfigurations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,namespace=kube-egress-gateway-system,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=egressgateway.kubernetes.azure.com,resources=gatewaystatuses,verbs=get;list;watch;create;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the StaticGatewayConfiguration object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile

var (
	nodeMeta       *imds.InstanceMetadata
	lbMeta         *imds.LoadBalancerMetadata
	nodeTags       map[string]string
	vmssInstanceRE = regexp.MustCompile(`.*/subscriptions/(.+)/resourceGroups/(.+)/providers/Microsoft.Compute/virtualMachineScaleSets/(.+)/virtualMachines/(.+)`)
)

func InitNodeMetadata() error {
	var err error
	nodeMeta, err = imds.GetInstanceMetadata()
	if err != nil {
		return err
	}
	lbMeta, err = imds.GetLoadBalancerMetadata()
	if err != nil {
		return err
	}
	if nodeMeta == nil || lbMeta == nil {
		return fmt.Errorf("failed to setup controller: nodeMeta or lbMeta is nil")
	}
	nodeTags = parseNodeTags()
	return nil
}

func (r *StaticGatewayConfigurationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Got an event from cleanup ticker
	if req.NamespacedName.Namespace == "" && req.NamespacedName.Name == "" {
		if err := r.cleanUp(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to clean up orphaned network configurations: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Fetch the StaticGatewayConfiguration instance.
	gwConfig := &egressgatewayv1alpha1.StaticGatewayConfiguration{}
	if err := r.Get(ctx, req.NamespacedName, gwConfig); err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, return.
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch StaticGatewayConfiguration instance")
		return ctrl.Result{}, err
	}

	if !isReady(gwConfig) {
		// gateway setup hasn't completed yet
		return ctrl.Result{}, nil
	}

	if !applyToNode(gwConfig) {
		// gwConfig does not apply to this node
		return ctrl.Result{}, nil
	}

	if !gwConfig.ObjectMeta.DeletionTimestamp.IsZero() {
		if err := r.cleanUp(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to clean up deleted StaticGatewayConfiguration %s/%s: %w", gwConfig.Namespace, gwConfig.Name, err)
		}
		return ctrl.Result{}, nil
	}

	// Reconcile gateway network configurations
	return ctrl.Result{}, r.reconcile(ctx, gwConfig)
}

// SetupWithManager sets up the controller with the Manager.
func (r *StaticGatewayConfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Netlink = netlinkwrapper.NewNetLink()
	r.IPTables = utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv4)
	r.WgCtrl = wgctrlwrapper.NewWgCtrl()
	controller, err := ctrl.NewControllerManagedBy(mgr).For(&egressgatewayv1alpha1.StaticGatewayConfiguration{}).Build(r)
	if err != nil {
		return err
	}
	return controller.Watch(&source.Channel{Source: r.TickerEvents}, &handler.EnqueueRequestForObject{})
}

func (r *StaticGatewayConfigurationReconciler) reconcile(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
) error {
	log := log.FromContext(ctx)
	log.Info("Reconciling gateway configuration")

	// get wireguard private key from secret
	privateKey, err := r.getWireguardPrivateKey(ctx, gwConfig)
	if err != nil {
		return err
	}

	// add lb ip (if not exists) to eth0
	if err := r.reconcileIlbIPOnHost(ctx, gwConfig.Status.GatewayServerProfile.Ip); err != nil {
		return err
	}

	// get vm primary IP and secondary IP
	_, vmSecondaryIP, err := r.getVMIP(ctx, gwConfig)
	if err != nil {
		return err
	}

	// configure gateway networking (if not exists)
	if err := r.configureGatewayNetworking(ctx, gwConfig, privateKey, vmSecondaryIP); err != nil {
		return err
	}

	// update gateway status
	gwStatus := egressgatewayv1alpha1.GatewayConfiguration{
		StaticGatewayConfiguration: fmt.Sprintf("%s/%s", gwConfig.Namespace, gwConfig.Name),
		InterfaceName:              getWireguardLinkName(gwConfig),
	}
	if err := r.updateGatewayNodeStatus(ctx, gwStatus, true /* add */); err != nil {
		return err
	}

	if err := r.LBProbeServer.AddGateway(string(gwConfig.GetUID())); err != nil {
		return err
	}

	log.Info("Gateway configuration reconciled")
	return nil
}

func (r *StaticGatewayConfigurationReconciler) cleanUp(ctx context.Context) error {
	log := log.FromContext(ctx)
	log.Info("Cleaning up orphaned gateway network configurations")

	gwConfigList := &egressgatewayv1alpha1.StaticGatewayConfigurationList{}
	if err := r.List(ctx, gwConfigList); err != nil {
		return fmt.Errorf("failed to list staticGatewayConfigurations: %w", err)
	}

	existingWgLinks := make(map[string]bool)
	hasActiveGateway := false
	for _, gwConfig := range gwConfigList.Items {
		if applyToNode(&gwConfig) && gwConfig.GetDeletionTimestamp().IsZero() {
			existingWgLinks[getWireguardLinkName(&gwConfig)] = true
			hasActiveGateway = true
		}
	}

	links, err := r.Netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}

	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, consts.WiregaurdLinkNamePrefix) && !existingWgLinks[link.Attrs().Name] {
			log.Info("Cleaning up link", "link", link.Attrs().Name)

			mark, err := getPacketMarkAndTableFromLinkName(link.Attrs().Name)
			if err != nil {
				log.Info("Failed to parse mark from link name", "link", link.Attrs().Name, "err", err)
				continue
			}
			log.Info("Got mark and table from link", "link", link.Attrs().Name, "mark", mark)

			// Delete routes
			routes, err := r.Netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{Table: mark}, netlink.RT_FILTER_TABLE)
			if err != nil {
				log.Info("Failed to list routes in table", "table", mark)
			}
			for _, route := range routes {
				route := route
				log.Info("Deleting route", "route", route)
				if err := r.Netlink.RouteDel(&route); err != nil {
					return fmt.Errorf("failed to delete route %s: %w", route, err)
				}
			}

			// Delete ip rule
			rules, err := r.Netlink.RuleList(nl.FAMILY_ALL)
			if err != nil {
				return fmt.Errorf("failed to list rules: %w", err)
			}
			for _, rule := range rules {
				rule := rule
				if rule.Mark == mark && rule.Table == mark {
					log.Info("Deleting rule", "rule", rule)
					if err := r.Netlink.RuleDel(&rule); err != nil {
						return fmt.Errorf("failed to delete rule %s: %w", rule, err)
					}
				}
			}

			// Delete iptables rules
			if err := r.removeIPTablesRule(ctx, link.Attrs().Name, mark); err != nil {
				return fmt.Errorf("failed to delete iptables rules for link %s: %w", link.Attrs().Name, err)
			}

			// Delete wireguard link
			log.Info("Deleting link", "link", link.Attrs().Name)
			if err := r.Netlink.LinkDel(link); err != nil {
				return fmt.Errorf("failed to delete link %s: %w", link.Attrs().Name, err)
			}

			// update gateway status
			gwStatus := egressgatewayv1alpha1.GatewayConfiguration{
				InterfaceName: link.Attrs().Name,
			}
			if err := r.updateGatewayNodeStatus(ctx, gwStatus, false /* add */); err != nil {
				return err
			}

			if err := r.LBProbeServer.RemoveGateway(link.Attrs().Alias); err != nil {
				return err
			}
		}
	}

	// TODO: left overs: ilbIP, iptables jump rules in 3 tables
	if !hasActiveGateway {
		log.Info("No active gateway, cleaning up leftovers")
		if err := r.reconcileIlbIPOnHost(ctx, ""); err != nil {
			return fmt.Errorf("failed to clean up ilb ip on eth0: %w", err)
		}

		if err := r.removeLeftoverIPTablesRules(ctx); err != nil {
			return fmt.Errorf("failed to clean up iptables rules: %w", err)
		}
	}

	log.Info("Network configurations cleanup completed")
	return nil
}

func (r *StaticGatewayConfigurationReconciler) getWireguardPrivateKey(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
) (*wgtypes.Key, error) {
	secretKey := &types.NamespacedName{
		Namespace: gwConfig.Status.PrivateKeySecretRef.Namespace,
		Name:      gwConfig.Status.PrivateKeySecretRef.Name,
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, *secretKey, secret); err != nil {
		return nil, fmt.Errorf("failed to retrieve wireguard private key secret: %w", err)
	}

	wgPrivateKeyByte, ok := secret.Data[consts.WireguardPrivateKeyName]
	if !ok {
		return nil, fmt.Errorf("failed to retrieve private key from secret %s/%s", secretKey.Namespace, secretKey.Name)
	}
	wgPrivateKey, err := wgtypes.ParseKey(string(wgPrivateKeyByte))
	if err != nil {
		return nil, err
	}
	return &wgPrivateKey, nil
}

func (r *StaticGatewayConfigurationReconciler) getVMIP(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
) (string, string, error) {
	log := log.FromContext(ctx)
	matches := vmssInstanceRE.FindStringSubmatch(nodeMeta.Compute.ResourceID)
	if len(matches) != 5 {
		return "", "", fmt.Errorf("failed to parse vmss instance resource ID: %s", nodeMeta.Compute.ResourceID)
	}
	subscriptionID, resourceGroupName, vmssName, instanceID := matches[1], matches[2], matches[3], matches[4]
	if subscriptionID != r.SubscriptionID() {
		return "", "", fmt.Errorf("node subscription(%s) is different from configured subscription(%s)", subscriptionID, r.SubscriptionID())
	}
	vm, err := r.GetVMSSInstance(ctx, resourceGroupName, vmssName, instanceID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get vmss instance: %w", err)
	}
	if vm.Properties == nil || vm.Properties.NetworkProfileConfiguration == nil {
		return "", "", fmt.Errorf("vm has empty network properties")
	}

	ipConfigName := gwConfig.Namespace + "_" + gwConfig.Name
	interfaces := vm.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations
	nicName := ""
	for _, nic := range interfaces {
		if nic.Properties != nil && to.Val(nic.Properties.Primary) {
			nicName = to.Val(nic.Name)
			break
		}
	}

	if nicName == "" {
		return "", "", fmt.Errorf("failed to find primary interface of vmss instance(%s_%s)", vmssName, instanceID)
	}
	nic, err := r.GetVMSSInterface(ctx, resourceGroupName, vmssName, instanceID, nicName)
	if err != nil {
		return "", "", fmt.Errorf("failed to get vmss instance primary interface: %w", err)
	}
	if nic.Properties == nil {
		return "", "", fmt.Errorf("nic has empty properties")
	}

	var primaryIP, ipConfigIP string
	for _, ipConfig := range nic.Properties.IPConfigurations {
		if ipConfig != nil && ipConfig.Properties != nil && strings.EqualFold(to.Val(ipConfig.Name), ipConfigName) {
			if ipConfig.Properties.PrivateIPAddress == nil {
				return "", "", fmt.Errorf("ipConfig(%s) does not have private ip address", ipConfigName)
			}
			ipConfigIP = to.Val(ipConfig.Properties.PrivateIPAddress)
			log.Info("Found vm ip corresponding to gwConfig", "IP", ipConfigIP)
		} else if ipConfig != nil && ipConfig.Properties != nil && to.Val(ipConfig.Properties.Primary) {
			if ipConfig.Properties.PrivateIPAddress == nil {
				return "", "", fmt.Errorf("primary ipConfig does not have ip address")
			}
			primaryIP = to.Val(ipConfig.Properties.PrivateIPAddress)
			log.Info("Found vm primary ip", "IP", primaryIP)
		}
	}

	if primaryIP == "" || ipConfigIP == "" {
		return "", "", fmt.Errorf("failed to find vm ips, primaryIP(%s), ipConfigIP(%s)", primaryIP, ipConfigIP)
	}
	return primaryIP, ipConfigIP, nil
}

func isReady(gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration) bool {
	wgProfile := gwConfig.Status.GatewayServerProfile
	return gwConfig.Status.EgressIpPrefix != "" && wgProfile.Ip != "" &&
		wgProfile.Port != 0 && wgProfile.PublicKey != "" &&
		wgProfile.PrivateKeySecretRef != nil
}

func applyToNode(gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration) bool {
	if gwConfig.Spec.GatewayNodepoolName != "" {
		name, ok := nodeTags[consts.AKSNodepoolTagKey]
		return ok && strings.EqualFold(name, gwConfig.Spec.GatewayNodepoolName)
	} else {
		vmssProfile := gwConfig.Spec.GatewayVmssProfile
		return strings.EqualFold(vmssProfile.VmssName, nodeMeta.Compute.VMScaleSetName) &&
			strings.EqualFold(vmssProfile.VmssResourceGroup, nodeMeta.Compute.ResourceGroupName)
	}
}

func parseNodeTags() map[string]string {
	tags := make(map[string]string)
	tagStrs := strings.Split(nodeMeta.Compute.Tags, ";")
	for _, tag := range tagStrs {
		kv := strings.Split(tag, ":")
		if len(kv) == 2 {
			tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return tags
}

func (r *StaticGatewayConfigurationReconciler) reconcileIlbIPOnHost(ctx context.Context, ilbIP string) error {
	log := log.FromContext(ctx)
	eth0, err := r.Netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to retrieve link eth0: %w", err)
	}

	if len(nodeMeta.Network.Interface) == 0 || len(nodeMeta.Network.Interface[0].IPv4.Subnet) == 0 {
		return fmt.Errorf("imds does not provide subnet information about the node")
	}
	prefix, err := strconv.Atoi(nodeMeta.Network.Interface[0].IPv4.Subnet[0].Prefix)
	if err != nil {
		return fmt.Errorf("failed to retrieve and parse prefix: %w", err)
	}

	addresses, err := r.Netlink.AddrList(eth0, nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to retrieve IP addresses for eth0: %w", err)
	}

	if ilbIP == "" {
		for _, address := range addresses {
			if address.Label == consts.ILBIPLabel {
				log.Info("Deleting ILB IP on eth0", "ilb ip", address.IPNet.String())
				if err := r.Netlink.AddrDel(eth0, &address); err != nil {
					return fmt.Errorf("failed to delete ILB IP from eth0: %w", err)
				}
			}
		}
		return nil
	}

	ilbIpCidr := fmt.Sprintf("%s/%d", ilbIP, prefix)
	ilbIpNet, err := netlink.ParseIPNet(ilbIpCidr)
	if err != nil {
		return fmt.Errorf("failed to parse ILB IP address: %s", ilbIpCidr)
	}

	addressPresent := false
	for _, address := range addresses {
		if address.IPNet.IP.Equal(ilbIpNet.IP) {
			addressPresent = true
			break
		}
	}

	if !addressPresent {
		log.Info("Adding ILB IP to eth0", "ilb IP", ilbIpCidr)
		if err := r.Netlink.AddrAdd(eth0, &netlink.Addr{
			Label: consts.ILBIPLabel,
			IPNet: ilbIpNet,
		}); err != nil {
			return fmt.Errorf("failed to add ILB IP to eth0: %w", err)
		}
	}
	return nil
}

func (r *StaticGatewayConfigurationReconciler) configureGatewayNetworking(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
	privateKey *wgtypes.Key,
	vmSecondaryIP string,
) error {
	if err := r.reconcileWireguardLink(ctx, gwConfig, privateKey); err != nil {
		return err
	}

	if err := r.reconcileRouting(ctx, gwConfig); err != nil {
		return err
	}

	if err := r.reconcileIPTables(ctx, gwConfig, vmSecondaryIP); err != nil {
		return err
	}
	return nil
}

func getWireguardLinkName(gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration) string {
	return consts.WiregaurdLinkNamePrefix + fmt.Sprintf("%d", gwConfig.Status.Port)
}

// getPacketMarkAndTable returns the packet mark and routing table number for each gwConfig.
// the number starts from 0x8000 and since the current port range is 6000-7000, the number spans from 0x8000 to 0x83e8
// the numbers in this range & 0x4000 == 0, which means they do not conflict with the packet mark used by kube-proxy
func getPacketMarkAndTable(gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration) int {
	return 0x8000 + int(gwConfig.Status.Port-consts.WireguardPortStart)
}

func getPacketMarkAndTableFromLinkName(wgLink string) (int, error) {
	if !strings.HasPrefix(wgLink, consts.WiregaurdLinkNamePrefix) {
		return -1, fmt.Errorf("invalid link name: %s", wgLink)
	}
	port, err := strconv.Atoi(strings.TrimPrefix(wgLink, consts.WiregaurdLinkNamePrefix))
	if err != nil {
		return -1, fmt.Errorf("failed to parse port from link name: %s, err: %w", wgLink, err)
	}
	return 0x8000 + (port - int(consts.WireguardPortStart)), nil
}

func (r *StaticGatewayConfigurationReconciler) reconcileWireguardLink(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
	privateKey *wgtypes.Key,
) error {
	log := log.FromContext(ctx)
	var wgLink netlink.Link
	var err error
	wgName := getWireguardLinkName(gwConfig)

	wgLink, err = r.Netlink.LinkByName(wgName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("failed to get wireguard link %s: %w", wgName, err)
		}
		wgLink = nil
	}

	if wgLink == nil {
		log.Info("Creating wireguard link")
		attr := netlink.NewLinkAttrs()
		attr.Name = wgName
		attr.Alias = string(gwConfig.GetUID())
		if err := r.Netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attr}); err != nil {
			return fmt.Errorf("failed to create wireguard link %s: %w", wgName, err)
		}
		wgLink, err = r.Netlink.LinkByName(wgName)
		if err != nil {
			return fmt.Errorf("failed to get wireguard link %s after creation: %w", wgName, err)
		}
	}

	gwIP, _ := netlink.ParseIPNet(consts.GatewayIP)
	gwLinkAddr := netlink.Addr{
		IPNet: gwIP,
	}

	wgLinkAddrs, err := r.Netlink.AddrList(wgLink, nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to retrieve address list from wireguard link %s: %w", wgName, err)
	}

	foundLink := false
	for _, addr := range wgLinkAddrs {
		if addr.Equal(gwLinkAddr) {
			log.Info("Found wireguard link address")
			foundLink = true
			break
		}
	}

	if !foundLink {
		log.Info("Adding wireguard link address")
		if err := r.Netlink.AddrAdd(wgLink, &gwLinkAddr); err != nil {
			return fmt.Errorf("failed to add wireguard link address on %s: %w", wgName, err)
		}
	}

	if err := r.Netlink.LinkSetUp(wgLink); err != nil {
		return fmt.Errorf("failed to set wireguard link %s up: %w", wgName, err)
	}

	wgClient, err := r.WgCtrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer func() { _ = wgClient.Close() }()

	wgConfig := wgtypes.Config{
		ListenPort: to.Ptr(int(gwConfig.Status.Port)),
		PrivateKey: privateKey,
	}

	device, err := wgClient.Device(wgName)
	if err != nil {
		return fmt.Errorf("failed to get wireguard link configuration for %s: %w", wgName, err)
	}

	if device.PrivateKey.String() != wgConfig.PrivateKey.String() || device.ListenPort != to.Val(wgConfig.ListenPort) {
		log.Info("Updating wireguard link config", "link name", wgName, "orig port", device.ListenPort, "cur port", to.Val(wgConfig.ListenPort),
			"private key difference", device.PrivateKey.String() != wgConfig.PrivateKey.String())
		err = wgClient.ConfigureDevice(wgName, wgConfig)
		if err != nil {
			return fmt.Errorf("failed to setup wireguard link %s: %w", wgLink, err)
		}
	}
	return nil
}

func (r *StaticGatewayConfigurationReconciler) reconcileRouting(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
) error {
	log := log.FromContext(ctx)
	eth0, err := r.Netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to retrieve link eth0: %w", err)
	}
	routes, err := r.Netlink.RouteList(eth0, nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list routes from eth0: %w", err)
	}

	var defaultGW net.IP
	for _, route := range routes {
		if route.Dst == nil {
			defaultGW = route.Gw
		}
	}

	tablemark := getPacketMarkAndTable(gwConfig)
	route := &netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Dst:       nil,
		Gw:        defaultGW,
		Table:     tablemark,
	}
	if err := r.Netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to create default route via eth0 in table %d: %w", tablemark, err)
	}

	rule := netlink.NewRule()
	rule.Mark = tablemark
	rule.Table = tablemark
	rules, err := r.Netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}
	foundRule := false
	for _, r := range rules {
		if r.Mark == rule.Mark && r.Table == rule.Table {
			foundRule = true
			break
		}
	}
	if !foundRule {
		log.Info("Adding rule", "fwmark", rule.Mark, "table", rule.Table)
		if err := r.Netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to add rule (fwmark %d table %d): %w", tablemark, tablemark, err)
		}
	}
	return nil
}

func (r *StaticGatewayConfigurationReconciler) reconcileIPTables(
	ctx context.Context,
	gwConfig *egressgatewayv1alpha1.StaticGatewayConfiguration,
	vmSecondaryIP string,
) error {
	log := log.FromContext(ctx)

	log.Info("Ensuring iptables rules in filter table")
	if err := r.ensureIPTablesChain(
		ctx,
		utiliptables.TableFilter, // table name
		utiliptables.Chain("EGRESS-GATEWAY-ALLOW-FORWARD"),                        // target chain
		utiliptables.ChainForward,                                                 // source chain
		"kube-egress-gateway allow packets fowarded from/to wireguard interfaces", // jump rule comment
		[][]string{
			{"-i", "wg+", "-o", "eth0", "-j", "ACCEPT"},
			{"-i", "eth0", "-o", "wg+", "-j", "ACCEPT"},
		}); err != nil {
		return err
	}

	log.Info("Ensuring iptables rules in mangle table")
	if err := r.ensureIPTablesChain(
		ctx,
		utiliptables.TableMangle, // table name
		utiliptables.Chain("EGRESS-GATEWAY-MARK"),                    // target chain
		utiliptables.ChainPrerouting,                                 // source chain
		"kube-egress-gateway mark packets from wireguard interfaces", // jump rule comment
		nil); err != nil {
		return err
	}

	mark := getPacketMarkAndTable(gwConfig)
	gwLink := getWireguardLinkName(gwConfig)
	if err := r.ensureIPTablesChain(
		ctx,
		utiliptables.TableMangle, // table name
		utiliptables.Chain(fmt.Sprintf("EGRESS-GATEWAY-MARK-0X%04X", mark)),         // target chain
		utiliptables.Chain("EGRESS-GATEWAY-MARK"),                                   // source chain
		fmt.Sprintf("kube-egress-gateway mark packets for gateway link %s", gwLink), // jump rule comment
		[][]string{
			{"-i", gwLink, "-j", "MARK", "--set-mark", fmt.Sprintf("%d", mark)},
			{"-i", gwLink, "-j", "CONNMARK", "--save-mark"},
			{"-i", gwLink, "-j", "ACCEPT"},
			{"-i", "eth0", "-m", "connmark", "--mark", fmt.Sprintf("%d", mark), "-j", "CONNMARK", "--restore-mark"},
		}); err != nil {
		return err
	}

	log.Info("Ensuring iptables rules in nat table")
	if err := r.ensureIPTablesChain(
		ctx,
		utiliptables.TableNAT, // table name
		utiliptables.Chain("EGRESS-GATEWAY-SNAT"),                    // target chain
		utiliptables.ChainPostrouting,                                // source chain
		"kube-egress-gateway SNAT packets from wireguard interfaces", // jump rule comment
		nil); err != nil {
		return err
	}

	if err := r.ensureIPTablesChain(
		ctx,
		utiliptables.TableNAT, // table name
		utiliptables.Chain(fmt.Sprintf("EGRESS-GATEWAY-SNAT-0X%04X", mark)),         // target chain
		utiliptables.Chain("EGRESS-GATEWAY-SNAT"),                                   // source chain
		fmt.Sprintf("kube-egress-gateway sNAT packets for gateway link %s", gwLink), // jump rule comment
		[][]string{
			{"-o", "eth0", "-m", "connmark", "--mark", fmt.Sprintf("%d", mark), "-j", "SNAT", "--to-source", vmSecondaryIP}, // not sure why, but -m mark --mark does not work...
		}); err != nil {
		return err
	}
	return nil
}

func (r *StaticGatewayConfigurationReconciler) removeIPTablesRule(
	ctx context.Context,
	linkName string,
	mark int,
) error {
	// delete iptables chain in mangle table
	if err := r.removeIPTablesChain(
		ctx,
		utiliptables.TableMangle, // table name
		utiliptables.Chain(fmt.Sprintf("EGRESS-GATEWAY-MARK-0X%04X", mark)),           // target chain
		utiliptables.Chain("EGRESS-GATEWAY-MARK"),                                     // source chain
		fmt.Sprintf("kube-egress-gateway mark packets for gateway link %s", linkName), // jump rule comment
	); err != nil {
		return err
	}

	// delete iptables chain in nat table
	if err := r.removeIPTablesChain(
		ctx,
		utiliptables.TableNAT, // table name
		utiliptables.Chain(fmt.Sprintf("EGRESS-GATEWAY-SNAT-0X%04X", mark)),           // target chain
		utiliptables.Chain("EGRESS-GATEWAY-SNAT"),                                     // source chain
		fmt.Sprintf("kube-egress-gateway sNAT packets for gateway link %s", linkName), // jump rule comment
	); err != nil {
		return err
	}

	return nil
}

func (r *StaticGatewayConfigurationReconciler) removeLeftoverIPTablesRules(ctx context.Context) error {
	// delete iptables chain in filter table
	if err := r.removeIPTablesChain(
		ctx,
		utiliptables.TableFilter, // table name
		utiliptables.Chain("EGRESS-GATEWAY-ALLOW-FORWARD"),                        // target chain
		utiliptables.ChainForward,                                                 // source chain
		"kube-egress-gateway allow packets fowarded from/to wireguard interfaces", // jump rule comment
	); err != nil {
		return err
	}

	// delete iptables chain in mangle table
	if err := r.removeIPTablesChain(
		ctx,
		utiliptables.TableMangle, // table name
		utiliptables.Chain("EGRESS-GATEWAY-MARK"),                    // target chain
		utiliptables.ChainPrerouting,                                 // source chain
		"kube-egress-gateway mark packets from wireguard interfaces", // jump rule comment
	); err != nil {
		return err
	}

	// delete iptables chain in nat table
	if err := r.removeIPTablesChain(
		ctx,
		utiliptables.TableNAT, // table name
		utiliptables.Chain("EGRESS-GATEWAY-SNAT"),                    // target chain
		utiliptables.ChainPostrouting,                                // source chain
		"kube-egress-gateway SNAT packets from wireguard interfaces", // jump rule comment
	); err != nil {
		return err
	}

	return nil
}

func (r *StaticGatewayConfigurationReconciler) ensureIPTablesChain(
	ctx context.Context,
	table utiliptables.Table,
	targetChain utiliptables.Chain,
	sourceChain utiliptables.Chain,
	jumpRuleComment string,
	chainRules [][]string,
) error {
	log := log.FromContext(ctx)

	// ensure target chain exists
	log.Info("Ensuring iptables chain", "table", table, "target chain", targetChain)
	if _, err := r.IPTables.EnsureChain(table, targetChain); err != nil {
		return fmt.Errorf("failed to ensure chain %s in table %s: %w", targetChain, table, err)
	}

	// ensure jump rule exists, we use EnsureRule because we do not want to flush all rules in the source chain
	log.Info("Ensuring jump rule", "source chain", sourceChain)
	if _, err := r.IPTables.EnsureRule(utiliptables.Prepend, table, sourceChain, "-m", "comment", "--comment", jumpRuleComment, "-j", string(targetChain)); err != nil {
		return fmt.Errorf("failed to ensure jump rule from chain %s to chain %s in table %s: %w", sourceChain, targetChain, table, err)
	}

	if len(chainRules) == 0 {
		return nil
	}

	// ensure all rules in the target chain atomically
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*"+string(table))
	writeLine(lines, utiliptables.MakeChainLine(targetChain))
	for _, rule := range chainRules {
		writeRule(lines, string(utiliptables.Append), targetChain, rule...)
	}
	writeLine(lines, "COMMIT")
	log.Info("Restoring rules", "rules", lines.String())
	if err := r.IPTables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return fmt.Errorf("failed to restore rules in chain %s in table %s: %w", targetChain, table, err)
	}
	return nil
}

func (r *StaticGatewayConfigurationReconciler) removeIPTablesChain(
	ctx context.Context,
	table utiliptables.Table,
	targetChain utiliptables.Chain,
	sourceChain utiliptables.Chain,
	jumpRuleComment string,
) error {
	log := log.FromContext(ctx)

	iptablesData := bytes.NewBuffer(nil)
	if err := r.IPTables.SaveInto(table, iptablesData); err != nil {
		return fmt.Errorf("failed to run iptables-save: %w", err)
	}

	existingChains := utiliptables.GetChainsFromTable(iptablesData.Bytes())
	if _, ok := existingChains[targetChain]; ok {
		// delete jump rule first
		log.Info("Deleting jump rule", "source chain", sourceChain, "target chain", targetChain)
		if err := r.IPTables.DeleteRule(table, sourceChain, "-m", "comment", "--comment", jumpRuleComment, "-j", string(targetChain)); err != nil {
			return fmt.Errorf("failed to delete jump rule from chain %s to chain %s in table %s: %w", sourceChain, targetChain, table, err)
		}

		log.Info("Flushing and deleting chain", "table", table, "target chain", targetChain)
		lines := bytes.NewBuffer(nil)
		writeLine(lines, "*"+string(table))
		writeLine(lines, utiliptables.MakeChainLine(targetChain))
		writeLine(lines, "-X", string(targetChain))
		writeLine(lines, "COMMIT")
		if err := r.IPTables.Restore(table, lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
			return fmt.Errorf("failed to restore rules in chain %s in table %s: %w", targetChain, table, err)
		}
	}

	return nil
}

// Similar syntax to utiliptables.Interface.EnsureRule, except you don't pass a table
// (you must write these rules under the line with the table name)
func writeRule(lines *bytes.Buffer, position string, chain utiliptables.Chain, args ...string) {
	fullArgs := append([]string{position, string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}

func (r *StaticGatewayConfigurationReconciler) updateGatewayNodeStatus(
	ctx context.Context,
	gwConfig egressgatewayv1alpha1.GatewayConfiguration,
	add bool,
) error {
	log := log.FromContext(ctx)
	gwStatusKey := types.NamespacedName{
		Namespace: os.Getenv(consts.PodNamespaceEnvKey),
		Name:      os.Getenv(consts.NodeNameEnvKey),
	}

	gwStatus := &egressgatewayv1alpha1.GatewayStatus{}
	if err := r.Get(ctx, gwStatusKey, gwStatus); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get existing gateway status object %s/%s", gwStatusKey.Namespace, gwStatusKey.Name)
			return err
		} else {
			if !add {
				// ignore creating object during cleanup
				return nil
			}

			// gwStatus does not exist, create a new one
			log.Info(fmt.Sprintf("Creating new gateway status(%s/%s)", gwStatusKey.Namespace, gwStatusKey.Name))

			node := &corev1.Node{}
			if err := r.Get(ctx, types.NamespacedName{Name: os.Getenv(consts.NodeNameEnvKey)}, node); err != nil {
				return fmt.Errorf("failed to get current node: %w", err)
			}

			gwStatus := &egressgatewayv1alpha1.GatewayStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gwStatusKey.Name,
					Namespace: gwStatusKey.Namespace,
				},
				Spec: egressgatewayv1alpha1.GatewayStatusSpec{
					ReadyGatewayConfigurations: []egressgatewayv1alpha1.GatewayConfiguration{gwConfig},
				},
			}
			if err := controllerutil.SetOwnerReference(node, gwStatus, r.Client.Scheme()); err != nil {
				return fmt.Errorf("failed to set gwStatus owner reference to node: %w", err)
			}
			log.Info("Creating new gateway status object")
			if err := r.Create(ctx, gwStatus); err != nil {
				return fmt.Errorf("failed to create gwStatus object: %w", err)
			}
		}
	} else {
		changed := false
		found := false
		for i, gwConf := range gwStatus.Spec.ReadyGatewayConfigurations {
			if gwConf.InterfaceName == gwConfig.InterfaceName {
				if !add {
					changed = true
					gwStatus.Spec.ReadyGatewayConfigurations = append(gwStatus.Spec.ReadyGatewayConfigurations[:i], gwStatus.Spec.ReadyGatewayConfigurations[i+1:]...)
				}
				found = true
				break
			}
		}
		if add && !found {
			gwStatus.Spec.ReadyGatewayConfigurations = append(gwStatus.Spec.ReadyGatewayConfigurations, gwConfig)
			changed = true
		}
		if !add {
			for i := len(gwStatus.Spec.ReadyPeerConfigurations) - 1; i >= 0; i = i - 1 {
				if gwStatus.Spec.ReadyPeerConfigurations[i].InterfaceName == gwConfig.InterfaceName {
					changed = true
					gwStatus.Spec.ReadyPeerConfigurations = append(gwStatus.Spec.ReadyPeerConfigurations[:i], gwStatus.Spec.ReadyPeerConfigurations[i+1:]...)
				}
			}
		}
		if changed {
			log.Info("Updating gateway status object")
			if err := r.Update(ctx, gwStatus); err != nil {
				return fmt.Errorf("failed to update gwStatus object: %w", err)
			}
		}
	}
	return nil
}
