[TOC]

# eviction manager

## 目标

本文档的主要目标是通过源码分析结合总结概述的方式试图让学习 kubernetes 的相关人员能对对 kubernetes 的 eviction manager 清晰、完整、深入的掌握.

## 总览

当 node 节点的可用计算资源过低时,需要一种机制来保证节点的稳定性,因此 eviction manager 应运而生. 通过 eviction manager 来实现 pod 驱逐,回收计算资源,以达到保证 node 节点的稳定性.

## eviction 触发的信号来源

既然是驱逐管理器,那我们首先应该想到的是,触发驱逐 pod 的条件是什么? 都有那些驱逐的策略? 当前版本(v1.14.1)中,驱逐的策略有如下几种:

| 名称                        | 描述                                                            |
| --------------------------- | --------------------------------------------------------------- |
| memory.available            | 可用内存                                                        |
| nodefs.available            | 可用文件系统大小                                                |
| nodefs.inodesFree           | 可用 inode                                                      |
| imagefs.available           | 容器运行时用于存储映像和容器可写层的文件系统上可用的存储量      |
| imagefs.inodesFree          | 容器运行时用于存储映像和容器可写层的文件系统上可用的 inode 数量 |
| allocatableMemory.available | 可用于调度 pod 的可用内存                                       |
| pid.available               | pod 可分配的 pid 数量                                           |

通过上面的表格可用看出目前的驱逐策略只支持 memory、fs、pid 相关的.并未支持 cpu.

## eviction 触发的阈值设置

驱逐策略有了, 那接下来就是触发驱逐策略的条件(阈值)了, 所有的驱逐策略的触发条件的设置都是形如:

```
<策略名称><操作><资源值 | 资源百分比>

```

- 策略名称 上表中的名称.
- 操作 所有的操作都是 **<** 符号.
- 资源值 k8s 资源值的字符串表示形式,如: 1Gi 1G 1024M 1024Mi 等, 或者是百分比的形式,如: 10% 12%等, 如果是百分比的形式则百分比的基数是 node 的某种资源的总值.

此外为了避免回收资源的效率,eviction manager 可以通过设置每次回收资源的最小值来实现

软驱逐的 flag 设置,例如:

```
--eviction-minimum-reclaim="memory.available=0Mi,nodefs.available=500Mi,imagefs.available=2Gi"
```

## 驱逐的分类

当前版本的 eviction manager 支持两种驱逐方式: 1. 软驱逐 2 硬驱逐, 接下来让我们分别来看看这两者,以及他们的区别

### 软驱逐

软驱逐需要管理员设置相应的驱逐的优雅驱逐宽限期,当设置的驱逐阈值达到时, kubelet 不会马上进行 pod 的驱逐操作, 只有超过驱逐宽限期后才会进行驱逐操作,除此之外, 如果已满足软驱逐阈值，则操作员可以指定节点驱逐 pod 时使用的最大允许 pod 终止宽限期。如果指定，则 evition manager 将使用两者中较小的值。如果未指定，则 kubelet 会在没有正常终止的情况下立即进行 pod 的驱逐操作.

软驱逐的 flag 设置:

```
--eviction-soft="": A set of eviction thresholds (e.g. memory.available<1.5Gi) that if met over a corresponding grace period would trigger a pod eviction.
--eviction-soft-grace-period="": A set of eviction grace periods (e.g. memory.available=1m30s) that correspond to how long a soft eviction threshold must hold before triggering a pod eviction.
--eviction-max-pod-grace-period="0": Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.
```

### 硬驱逐

硬驱逐当设置的驱逐阈值达到时,立即进行 pod 的驱逐操作, pod 没有优雅退出的时间.

硬驱逐的 flag 设置:

```
--eviction-hard="": A set of eviction thresholds (e.g. memory.available<1Gi) that if met would trigger a pod eviction.
```

## cgroup memory notifier

目前 kubelet 获取的所有的时时阈值设置的资源类型都是通过 cadvisor 获取的, 如果开启这个参数, 则当内存使用超过设置的内存的驱逐阈值时,通过 linux kernel 的 cgroup 事件来通知 eviction manager 去做驱逐 pod 的操作.

```
--experimental-kernel-memcg-notification
If enabled, the kubelet will integrate with the kernel memcg notification to determine if memory eviction thresholds are crossed rather than polling.
```

## 驱逐对 pod 的影响

BestEffort pod 消耗最大的阈值资源 将先驱逐

Burstable 如果 pod 的资源使用超过了其请求值,则使用最多的将先驱逐,如果资源没有超过其请求值,则当前使用资源最多的将被驱逐

Guaranteed 如果 pod 的资源使用超过了其请求值,则使用最多的将先驱逐,如果资源没有超过其请求值,则当前使用资源最多的将被驱逐

## 驱逐对 node 的状态的影响

当驱逐策略设置的阈值达到时, 会相应的影响到 node 的状态,主要是 MemoryPressure 和 DiskPressure.

| 节点状态       | 驱逐策略名称                                                               | 状态描述 |
| -------------- | -------------------------------------------------------------------------- | -------- |
| MemoryPressure | memory.available                                                           | 内存压力 |
| DiskPressure   | nodefs.available, nodefs.inodesFree, imagefs.available, imagefs.inodesFree | 磁盘压力 |

## 驱逐对调度的影响

当 node 满足 MemoryPressure 状态时, 调度器会阻止 BestEffort 类型的 pod 调度到该 node 上,当 node 满足 DiskPressure 状态时将阻止所有新建的 pod 调度到该 node 上.

## 源码分析

通过上面的讲解,接下来我们来分析对应的 eviction manager 的源码. 在分析源码之前我们先来想想, eviction 要实现 pod 的驱逐,从而来达到资源回收的能力, 都需要做些什么样的操作. 不妨大胆的作如下假设:

因为驱逐管理其是根据命令行参数设置的对应的驱逐策略的阈值, 从而来周期性的检查对应的资源有没有达到对应的阈值, 以此来判断是否进行驱逐 pod,从而回收资源. 那资源的对应的监控的资源的数据来源从哪里来? 当某种资源达到来阈值之后,需要筛选出驱逐的 pod,满足驱逐条件的 pod 又是从哪里来? 如何驱逐 pod 的? 如何去更新 node 的状态? 有了以上的几个问题之后,我们自然会想到 manager 中大概会有几个核心的 struct 或者是子 manager? 通过上面的假设,我们可以试想下 eviction manager 大致的一个工作流程: eviction manager 获取对应的设置的驱逐策健值对,然后周期性的采集对应的内存和磁盘的时时使用数据, 然后和对应的资源设置的驱逐策略阈值进行比较, 如果达到驱逐的阈值, 则就根据驱逐的策略(可能是软硬同时存在),筛选出可驱逐的 pod,然后进行 pod 的停止,资源回收操作(可能包含容器和 image 等).

### 驱逐策略以及操作的设置的源码

代码路径: `kubernetes/pkg/kubelet/eviction/api/types.go`

```go
package api

import (
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// Signal defines a signal that can trigger eviction of pods on a node.
type Signal string

const (
	SignalMemoryAvailable Signal = "memory.available"
	SignalNodeFsAvailable Signal = "nodefs.available"
	SignalNodeFsInodesFree Signal = "nodefs.inodesFree"
	SignalImageFsAvailable Signal = "imagefs.available"
	SignalImageFsInodesFree Signal = "imagefs.inodesFree"
	SignalAllocatableMemoryAvailable Signal = "allocatableMemory.available"
	SignalPIDAvailable Signal = "pid.available"
)

type ThresholdOperator string

const (
	OpLessThan ThresholdOperator = "LessThan"
)

var OpForSignal = map[Signal]ThresholdOperator{
	SignalMemoryAvailable:   OpLessThan,
	SignalNodeFsAvailable:   OpLessThan,
	SignalNodeFsInodesFree:  OpLessThan,
	SignalImageFsAvailable:  OpLessThan,
	SignalImageFsInodesFree: OpLessThan,
	SignalPIDAvailable:      OpLessThan,
}

// ThresholdValue 用于存储我们设置的阈值
type ThresholdValue struct {
	Quantity *resource.Quantity
	Percentage float32
}

// Threshold 用于存储我们通过kubelet启动参数指定的一个完整驱逐的策略.
type Threshold struct {
	Signal Signal
	Operator ThresholdOperator
	Value ThresholdValue
	GracePeriod time.Duration
	MinReclaim *ThresholdValue
}
```

相关的整理都在表一中.

### manager

在源码中,eviction manager 是一个接口, 真正工作是由其实现 struct 去做的, 接下来我们先来看看对应的接口以及相关子接口

代码路径: `kubernetes/pkg/kubelet/eviction/types.go`

```go
// Manager evaluates when an eviction threshold for node stability has been met on the node.
type Manager interface {
	// Start starts the control loop to monitor eviction thresholds at specified interval.
	Start(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc, podCleanedUpFunc PodCleanedUpFunc, monitoringInterval time.Duration)

	// IsUnderMemoryPressure returns true if the node is under memory pressure.
	IsUnderMemoryPressure() bool

	// IsUnderDiskPressure returns true if the node is under disk pressure.
	IsUnderDiskPressure() bool

	// IsUnderPIDPressure returns true if the node is under PID pressure.
	IsUnderPIDPressure() bool
}

- start 方法就是用来周期性的做资源收集, 比较,驱逐 pod,回收资源的操作的.
- IsUnderMemoryPressure IsUnderDiskPressure IsUnderPIDPressure 这三个方法主要是 kubelet 的 node status manager 使用的. eviction manager 没有使用到.
```

通过 start 方法的三个参数，大体验证了我们之前的猜测。 diskInfoProvider 收集资源， podFunc 筛选 pod, podCleanedUpFunc 确认 pod 资源回收是否完成, monitoringInterval 执行 eviction 的轮训周期.

#### manager 实现

代码路径: `kubernetes/pkg/kubelet/eviction/eviction_manager.go`

```go
// managerImpl implements Manager
type managerImpl struct {
	//  used to track time
	clock clock.Clock
	// config is how the manager is configured
	config Config
	// the function to invoke to kill a pod
	killPodFunc KillPodFunc
	// the function to get the mirror pod by a given statid pod
	mirrorPodFunc MirrorPodFunc
	// the interface that knows how to do image gc
	imageGC ImageGC
	// the interface that knows how to do container gc
	containerGC ContainerGC
	// protects access to internal state
	sync.RWMutex
	// node conditions are the set of conditions present
	nodeConditions []v1.NodeConditionType
	// captures when a node condition was last observed based on a threshold being met
	nodeConditionsLastObservedAt nodeConditionsObservedAt
	// nodeRef is a reference to the node
	nodeRef *v1.ObjectReference
	// used to record events about the node
	recorder record.EventRecorder
	// used to measure usage stats on system
	summaryProvider stats.SummaryProvider
	// records when a threshold was first observed
	thresholdsFirstObservedAt thresholdsObservedAt
	// records the set of thresholds that have been met (including graceperiod) but not yet resolved
	thresholdsMet []evictionapi.Threshold
	// signalToRankFunc maps a resource to ranking function for that resource.
	signalToRankFunc map[evictionapi.Signal]rankFunc
	// signalToNodeReclaimFuncs maps a resource to an ordered list of functions that know how to reclaim that resource.
	signalToNodeReclaimFuncs map[evictionapi.Signal]nodeReclaimFuncs
	// last observations from synchronize
	lastObservations signalObservations
	// dedicatedImageFs indicates if imagefs is on a separate device from the rootfs
	dedicatedImageFs *bool
	// thresholdNotifiers is a list of memory threshold notifiers which each notify for a memory eviction threshold
	thresholdNotifiers []ThresholdNotifier
	// thresholdsLastUpdated is the last time the thresholdNotifiers were updated.
	thresholdsLastUpdated time.Time
}

func NewManager(
	summaryProvider stats.SummaryProvider,
	config Config,
	killPodFunc KillPodFunc,
	mirrorPodFunc MirrorPodFunc,
	imageGC ImageGC,
	containerGC ContainerGC,
	recorder record.EventRecorder,
	nodeRef *v1.ObjectReference,
	clock clock.Clock,
) (Manager, lifecycle.PodAdmitHandler) {
	manager := &managerImpl{
		clock:                        clock,
		killPodFunc:                  killPodFunc,
		mirrorPodFunc:                mirrorPodFunc,
		imageGC:                      imageGC,
		containerGC:                  containerGC,
		config:                       config,
		recorder:                     recorder,
		summaryProvider:              summaryProvider,
		nodeRef:                      nodeRef,
		nodeConditionsLastObservedAt: nodeConditionsObservedAt{},
		thresholdsFirstObservedAt:    thresholdsObservedAt{},
		dedicatedImageFs:             nil,
		thresholdNotifiers:           []ThresholdNotifier{},
	}
	return manager, manager
}
```

相关的参数就不在叙述了,有对应的注释.

既然是源码讲解，那我个人觉得就是要将对应的结构体的初始化的各个数据来源都讲清楚，然后才是代码功能逻辑处理的代码分析， 既然要讲清楚 eviction manager 接口实现的各个 struct filed 的来源,哪肯定我们得知道是谁,在什么地方需要使用他？肯定是需要使用他的地方去初始化各种 filed。

初始化

代码路径: `kuberenetes/pkg/kubelet/kubelet.go 825`

```
func NewMainKubelet(...)  (*Kubelet, error)  {
	------
	evictionManager, evictionAdmitHandler := eviction.NewManager(klet.resourceAnalyzer, evictionConfig, killPodNow(klet.podWorkers, kubeDeps.Recorder), klet.podManager.GetMirrorPodByPod, klet.imageManager, klet.containerGC, kubeDeps.Recorder, nodeRef, klet.clock)
	------
}
```

我们需要记住几个核心的参数的来源:

1. stats.SummaryProvider klet.resourceAnalyzer 主要实现指标数据采集的方法
2. Config eviction.Config{
   PressureTransitionPeriod: kubeCfg.EvictionPressureTransitionPeriod.Duration,
   MaxPodGracePeriodSeconds: int64(kubeCfg.EvictionMaxPodGracePeriod),
   Thresholds: thresholds,
   KernelMemcgNotification: experimentalKernelMemcgNotification,
   PodCgroupRoot: kubeDeps.ContainerManager.GetPodCgroupRoot(),
   } 主要是通过 kubelet 的驱逐相关的 flag 参数设置的驱逐策略健值对
3. KillPodFunc killPodNow(klet.podWorkers, kubeDeps.Recorder) 用于删除 pod
4. MirrorPodFunc klet.podManager.GetMirrorPodByPod 用于获取 mirropod
5. ImageGC klet.imageManager 用于镜像相关的操作(比如回收资源等)
6. ContainerGC klet.containerGC 用于容器的垃圾回收

接下来我们将上面列出的核心参数的具体实现方式进行详细的代码分析:

1. klet.resourceAnalyzer 分析

// ResourceAnalyzer provides statistics on node resource consumption
type ResourceAnalyzer interface {
Start()

    fsResourceAnalyzerInterface
    SummaryProvider

}

type resourceAnalyzer struct {
\*fsResourceAnalyzer 主要是用于方便管理 pod 使用相关的本地存储挂载
SummaryProvider 主要是 kubelet 自己暴露的关于 node 和 pod 的 cpu 内存相关的 restful 接口的底层实现,最终是对接到 cadvisor
}

klet.resourceAnalyzer = serverstats.NewResourceAnalyzer(klet, kubeCfg.VolumeStatsAggPeriod.Duration)

2. config 就不在细说了 就是通过 flag 参数初始化到 kubelet 的 config,然后从 kubelet 的 config 获取对应策略健值对.

3. KillPodFunc

```
func killPodNow(podWorkers PodWorkers, recorder record.EventRecorder) eviction.KillPodFunc {
	return func(pod *v1.Pod, status v1.PodStatus, gracePeriodOverride *int64) error {

		// 设置优雅退出时间,如果有设置驱逐的时间则用该时间,如果没有设置,默认用kubelet在创建pod时spec中设置的TerminationGracePeriodSeconds值,默认是30秒
		gracePeriod := int64(0)
		if gracePeriodOverride != nil {
			gracePeriod = *gracePeriodOverride
		} else if pod.Spec.TerminationGracePeriodSeconds != nil {
			gracePeriod = *pod.Spec.TerminationGracePeriodSeconds
		}

		// 删除pod的超时时间,由于我们设置的pod的优雅退出时间,所有这个超时时间是建立在优雅退出时间之上的,肯定比优雅退出时间大,如果比他小,我们则设置默认的最小超时时间为10秒,那什么时候会比他小呢? 当我们在kubelet启动参数中设置的驱逐的优雅时间或者pod.spec.TerminationGracePeriodSeconds中设置的值较小时,会出现这种情况.
		//
		kubelet->runtime traffic to complete in sigkill)
		timeout := int64(gracePeriod + (gracePeriod / 2))
		minTimeout := int64(10)
		if timeout < minTimeout {
			timeout = minTimeout
		}
		timeoutDuration := time.Duration(timeout) * time.Second

		// open a channel we block against until we get a result
		type response struct {
			err error
		}
		ch := make(chan response, 1)

		// 封装参数调用podWorkers.UpdatePod 更新pod
		podWorkers.UpdatePod(&UpdatePodOptions{
			Pod:        pod,
			UpdateType: kubetypes.SyncPodKill,
			OnCompleteFunc: func(err error) {
				ch <- response{err: err}
			},
			KillPodOptions: &KillPodOptions{
				PodStatusFunc: func(p *v1.Pod, podStatus *kubecontainer.PodStatus) v1.PodStatus {
					return status
				},
				PodTerminationGracePeriodSecondsOverride: gracePeriodOverride,
			},
		})

		// 超时或者出错,我们做事件的广播
		select {
		case r := <-ch:
			return r.err
		case <-time.After(timeoutDuration):
			recorder.Eventf(pod, v1.EventTypeWarning, events.ExceededGracePeriod, "Container runtime did not kill the pod within specified grace period.")
			return fmt.Errorf("timeout waiting to kill pod")
		}
	}
}
```

podWorkers 主要是用来删除 pod 用的启动

recorder 主要用来产生事件

接下来整理下代码逻辑:
通过参数 gracePeriodOverride(值的来源在上一节 **软驱逐** 中说明了) 判断是否有替代的 killpod 的优雅回收时间,如果有则用此时间去更新 pod 为删除,因为 killpod 的操作是有 podwork 去调用用 container runtim api 去实现的,并且有优雅退出时间,所有是一个阻塞操作,所有需要设置一个超时时间,在有允许的时间范围内去发送 synckillpod 信号到 runtime.2

4. MirrorPodFunc

代码路径: k8s.io/kubernetes/pkg/kubelet/pod/pod_manager.go 373

func (pm *basicManager) GetMirrorPodByPod(pod *v1.Pod) (\*v1.Pod, bool) {
pm.lock.RLock()
defer pm.lock.RUnlock()
mirrorPod, ok := pm.mirrorPodByFullName[kubecontainer.GetPodFullName(pod)]
return mirrorPod, ok
}

这里我就不在说 basicManager 的实现, GetMirrorPodByPod 主要是获取 mirropod, 我简单的说下什么是 mirro pod.

说到 mirro pod 那就肯定离不开 static pod 了, 相关的介绍官网有,我就简单的说下,static pod 是通过 kubelet 的启动参数中 podmanifest 文件路或者是 podmanifest-url 指定的地址中的静态 json 或者 yaml 文件创建出来的 pod,这个 pod 是不归 kube-apiserver 管理的, 是 kubelet 自己管理, 但是人们在使用 k8s 的时候通常是用使用 kube-apiserver 的 api 或者使用 kubectl,这就就不能方便的管理 static pod 了, 所以, 在 kubelet 启动的时候,只要有 static pod 创建就会调用 kube-apiserver 的接口去创建一个对应的 static pod 的 pod 到 apiserver 中去,mirro pod 有一个特殊的 annotation "kubernetes.io/config.mirror" key.

接下来,我们说说为什么 evtion manager 中需要用到 mirro pod 呢? 因为 static pod 在驱逐的时候(在此我先说明下: 需要驱逐的 pod 必须是 running 的),我们是需要排除 mirro pod, 为什么需要排除 mirro pod 呢? 因为 mirro pod 不受调度影响,你驱逐之后马上 kubelet 就会拉起一个新的 static pod. 从而新建一个 mirro pod. 等下我们可以看 evitionPod 的方法的代码.

5. imageGC 是用于垃圾回收 image 所占用的磁盘资源的
6. containerGC pod 删除之后用于回收垃圾容器的
   **关于 imagegc 和 containergc 可以查看 kubelet_gc.md []**

启动

代码路径: `kuberenetes/pkg/kubelet/kubelet.go 1340`

func (kl \*Kubelet) initializeRuntimeDependentModules() {
kl.evictionManager.Start(kl.StatsProvider, kl.GetActivePods, kl.podResourcesAreReclaimed, evictionMonitoringPeriod)

}

启动的时候传入了三个核心参数, evictionManager 的 start 方法需要三个参数.

1. DiskInfoProvider kl.StatsProvider 这里主要有用到一个方法判断 node 是否使用用额外的 rootfs 做 image 的存储
2. ActivePodsFunc kl.GetActivePods 主要是获取 running 的 pod
3. PodCleanedUpFunc kl.podResourcesAreReclaimed 主要是判断删除的 pod 相关的资源是否回收完成

接下来我们将上面列出的核心参数的具体实现方式进行详细的代码分析:

1. kl.StatsProvider

代码路径: kubernetes/pkg/kubelet/stats/stats_provider.go 203

```
   // 是否存在专用的镜像文件系统
   func (p *StatsProvider) HasDedicatedImageFs() (bool, error) {
   device, err := p.containerStatsProvider.ImageFsDevice()
   if err != nil {
   return false, err
   }
   rootFsInfo, err := p.cadvisor.RootFsInfo()
   if err != nil {
   return false, err
   }
   return device != rootFsInfo.Device, nil
   }
```

2. kl.GetActivePods 获取 running 的 pod

代码路径: kubernetes/pkg/kubelete/kubelet_pods.go

```
// GetActivePods returns non-terminal pods
func (kl *Kubelet) GetActivePods() []*v1.Pod {
allPods := kl.podManager.GetPods()
activePods := kl.filterOutTerminatedPods(allPods)
return activePods
}

// filterOutTerminatedPods returns the given pods which the status manager
// does not consider failed or succeeded.
func (kl *Kubelet) filterOutTerminatedPods(pods []*v1.Pod) []*v1.Pod {
var filteredPods []*v1.Pod
for \_, p := range pods {
if kl.podIsTerminated(p) {
continue
}
filteredPods = append(filteredPods, p)
}
return filteredPods
}


// podIsTerminated returns true if pod is in the terminated state ("Failed" or "Succeeded").
func (kl *Kubelet) podIsTerminated(pod *v1.Pod) bool {
// Check the cached pod status which was set after the last sync.
status, ok := kl.statusManager.GetPodStatus(pod.UID)
if !ok {
// If there is no cached status, use the status from the
// apiserver. This is useful if kubelet has recently been
// restarted.
status = pod.Status
}
return status.Phase == v1.PodFailed || status.Phase == v1.PodSucceeded || (pod.DeletionTimestamp != nil && notRunning(status.ContainerStatuses))
}
```

3. kl.podResourcesAreReclaimed 确认 killed pod 是都资源都回收完成

代码路径: `kubernetes/pkg/kubelete/kubelet_pods.go 936`

```
func (kl *Kubelet) podResourcesAreReclaimed(pod *v1.Pod) bool {
	status, ok := kl.statusManager.GetPodStatus(pod.UID)
	if !ok {
		status = pod.Status
	}
	return kl.PodResourcesAreReclaimed(pod, status)
}

主要是检查是否还有pod相关连的容器在运行,pod相关连的volume对应的目录存在,以及对应sandbox容器是否清楚完成
func (kl *Kubelet) PodResourcesAreReclaimed(pod *v1.Pod, status v1.PodStatus) bool {
	if !notRunning(status.ContainerStatuses) {
		// We shouldnt delete pods that still have running containers
		klog.V(3).Infof("Pod %q is terminated, but some containers are still running", format.Pod(pod))
		return false
	}
	// pod's containers should be deleted
	runtimeStatus, err := kl.podCache.Get(pod.UID)
	if err != nil {
		klog.V(3).Infof("Pod %q is terminated, Error getting runtimeStatus from the podCache: %s", format.Pod(pod), err)
		return false
	}
	if len(runtimeStatus.ContainerStatuses) > 0 {
		var statusStr string
		for _, status := range runtimeStatus.ContainerStatuses {
			statusStr += fmt.Sprintf("%+v ", *status)
		}
		klog.V(3).Infof("Pod %q is terminated, but some containers have not been cleaned up: %s", format.Pod(pod), statusStr)
		return false
	}
	if kl.podVolumesExist(pod.UID) && !kl.keepTerminatedPodVolumes {
		// We shouldnt delete pods whose volumes have not been cleaned up if we are not keeping terminated pod volumes
		klog.V(3).Infof("Pod %q is terminated, but some volumes have not been cleaned up", format.Pod(pod))
		return false
	}
	if kl.kubeletConfiguration.CgroupsPerQOS {
		pcm := kl.containerManager.NewPodContainerManager()
		if pcm.Exists(pod) {
			klog.V(3).Infof("Pod %q is terminated, but pod cgroup sandbox has not been cleaned up", format.Pod(pod))
			return false
		}
	}
	return true
}
```

到目前为止, 我们的 eviction manager 为了实现驱逐 pod 的功能所需要所有的资源都已经准备好, 那接下来就开始干活了. 到底是如何做驱逐 pod 的操作的呢? 我们来看看 start 方法,然后一步步的顺着源代码分析下去:

#### Start

```
// Start starts the control loop to observe and response to low compute resources.
func (m *managerImpl) Start(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc, podCleanedUpFunc PodCleanedUpFunc, monitoringInterval time.Duration) {
	thresholdHandler := func(message string) {
		klog.Infof(message)
		m.synchronize(diskInfoProvider, podFunc)
	}
	if m.config.KernelMemcgNotification {
		for _, threshold := range m.config.Thresholds {
			if threshold.Signal == evictionapi.SignalMemoryAvailable || threshold.Signal == evictionapi.SignalAllocatableMemoryAvailable {
				notifier, err := NewMemoryThresholdNotifier(threshold, m.config.PodCgroupRoot, &CgroupNotifierFactory{}, thresholdHandler)
				if err != nil {
					klog.Warningf("eviction manager: failed to create memory threshold notifier: %v", err)
				} else {
					go notifier.Start()
					m.thresholdNotifiers = append(m.thresholdNotifiers, notifier)
				}
			}
		}
	}
	// start the eviction manager monitoring
	go func() {
		for {
			if evictedPods := m.synchronize(diskInfoProvider, podFunc); evictedPods != nil {
				klog.Infof("eviction manager: pods %s evicted, waiting for pod to be cleaned up", format.Pods(evictedPods))
				m.waitForPodsCleanup(podCleanedUpFunc, evictedPods)
			} else {
				time.Sleep(monitoringInterval)
			}
		}
	}()
}
```

代码处理逻辑: 首先是初始化一个 thresholdHandler 方法,用来处理驱逐 pod.用来初始化 cgroup 的 MemoryThresholdNotifier, 然后根据参数去判断是否使用了 cgroup memory notifier 通过上文中提到的 cgroup memory 参数,新建一个 cgroup 的 MemoryThresholdNotifier 加入到 eviction manager 中的通知器中.
最后通过 monitoringInterval 这个驱逐器执行的周期时间来周期性的执行 synchronize 这个同步驱逐的方法. 真正处理驱逐逻辑判断的方法是 synchronize 方法,然后我们来详细的分析这个方法的代码.

#### synchronize

```
func (m *managerImpl) synchronize(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc) []*v1.Pod {
	// if we have nothing to do, just return
	thresholds := m.config.Thresholds
	if len(thresholds) == 0 && !utilfeature.DefaultFeatureGate.Enabled(features.LocalStorageCapacityIsolation) {
		return nil
	}

	klog.V(3).Infof("eviction manager: synchronize housekeeping")
	// build the ranking functions (if not yet known)
	// TODO: have a function in cadvisor that lets us know if global housekeeping has completed
	if m.dedicatedImageFs == nil {
		hasImageFs, ok := diskInfoProvider.HasDedicatedImageFs()
		if ok != nil {
			return nil
		}
		m.dedicatedImageFs = &hasImageFs
		m.signalToRankFunc = buildSignalToRankFunc(hasImageFs)
		m.signalToNodeReclaimFuncs = buildSignalToNodeReclaimFuncs(m.imageGC, m.containerGC, hasImageFs)
	}

	activePods := podFunc()
	updateStats := true
	summary, err := m.summaryProvider.Get(updateStats)
	if err != nil {
		klog.Errorf("eviction manager: failed to get summary stats: %v", err)
		return nil
	}

	if m.clock.Since(m.thresholdsLastUpdated) > notifierRefreshInterval {
		m.thresholdsLastUpdated = m.clock.Now()
		for _, notifier := range m.thresholdNotifiers {
			if err := notifier.UpdateThreshold(summary); err != nil {
				klog.Warningf("eviction manager: failed to update %s: %v", notifier.Description(), err)
			}
		}
	}

	// make observations and get a function to derive pod usage stats relative to those observations.
	observations, statsFunc := makeSignalObservations(summary)
	debugLogObservations("observations", observations)

	// determine the set of thresholds met independent of grace period
	thresholds = thresholdsMet(thresholds, observations, false)
	debugLogThresholdsWithObservation("thresholds - ignoring grace period", thresholds, observations)

	// determine the set of thresholds previously met that have not yet satisfied the associated min-reclaim
	if len(m.thresholdsMet) > 0 {
		thresholdsNotYetResolved := thresholdsMet(m.thresholdsMet, observations, true)
		thresholds = mergeThresholds(thresholds, thresholdsNotYetResolved)
	}
	debugLogThresholdsWithObservation("thresholds - reclaim not satisfied", thresholds, observations)

	// track when a threshold was first observed
	now := m.clock.Now()
	thresholdsFirstObservedAt := thresholdsFirstObservedAt(thresholds, m.thresholdsFirstObservedAt, now)

	// the set of node conditions that are triggered by currently observed thresholds
	nodeConditions := nodeConditions(thresholds)
	if len(nodeConditions) > 0 {
		klog.V(3).Infof("eviction manager: node conditions - observed: %v", nodeConditions)
	}

	// track when a node condition was last observed
	nodeConditionsLastObservedAt := nodeConditionsLastObservedAt(nodeConditions, m.nodeConditionsLastObservedAt, now)

	// node conditions report true if it has been observed within the transition period window
	nodeConditions = nodeConditionsObservedSince(nodeConditionsLastObservedAt, m.config.PressureTransitionPeriod, now)
	if len(nodeConditions) > 0 {
		klog.V(3).Infof("eviction manager: node conditions - transition period not met: %v", nodeConditions)
	}

	// determine the set of thresholds we need to drive eviction behavior (i.e. all grace periods are met)
	thresholds = thresholdsMetGracePeriod(thresholdsFirstObservedAt, now)
	debugLogThresholdsWithObservation("thresholds - grace periods satisified", thresholds, observations)

	// update internal state
	m.Lock()
	m.nodeConditions = nodeConditions
	m.thresholdsFirstObservedAt = thresholdsFirstObservedAt
	m.nodeConditionsLastObservedAt = nodeConditionsLastObservedAt
	m.thresholdsMet = thresholds

	// determine the set of thresholds whose stats have been updated since the last sync
	thresholds = thresholdsUpdatedStats(thresholds, observations, m.lastObservations)
	debugLogThresholdsWithObservation("thresholds - updated stats", thresholds, observations)

	m.lastObservations = observations
	m.Unlock()

	// evict pods if there is a resource usage violation from local volume temporary storage
	// If eviction happens in localStorageEviction function, skip the rest of eviction action
	if utilfeature.DefaultFeatureGate.Enabled(features.LocalStorageCapacityIsolation) {
		if evictedPods := m.localStorageEviction(summary, activePods); len(evictedPods) > 0 {
			return evictedPods
		}
	}

	if len(thresholds) == 0 {
		klog.V(3).Infof("eviction manager: no resources are starved")
		return nil
	}

	// rank the thresholds by eviction priority
	sort.Sort(byEvictionPriority(thresholds))
	thresholdToReclaim := thresholds[0]
	resourceToReclaim, found := signalToResource[thresholdToReclaim.Signal]
	if !found {
		klog.V(3).Infof("eviction manager: threshold %s was crossed, but reclaim is not implemented for this threshold.", thresholdToReclaim.Signal)
		return nil
	}
	klog.Warningf("eviction manager: attempting to reclaim %v", resourceToReclaim)

	// record an event about the resources we are now attempting to reclaim via eviction
	m.recorder.Eventf(m.nodeRef, v1.EventTypeWarning, "EvictionThresholdMet", "Attempting to reclaim %s", resourceToReclaim)

	// check if there are node-level resources we can reclaim to reduce pressure before evicting end-user pods.
	if m.reclaimNodeLevelResources(thresholdToReclaim.Signal, resourceToReclaim) {
		klog.Infof("eviction manager: able to reduce %v pressure without evicting pods.", resourceToReclaim)
		return nil
	}

	klog.Infof("eviction manager: must evict pod(s) to reclaim %v", resourceToReclaim)

	// rank the pods for eviction
	rank, ok := m.signalToRankFunc[thresholdToReclaim.Signal]
	if !ok {
		klog.Errorf("eviction manager: no ranking function for signal %s", thresholdToReclaim.Signal)
		return nil
	}

	// the only candidates viable for eviction are those pods that had anything running.
	if len(activePods) == 0 {
		klog.Errorf("eviction manager: eviction thresholds have been met, but no pods are active to evict")
		return nil
	}

	// rank the running pods for eviction for the specified resource
	rank(activePods, statsFunc)

	klog.Infof("eviction manager: pods ranked for eviction: %s", format.Pods(activePods))

	//record age of metrics for met thresholds that we are using for evictions.
	for _, t := range thresholds {
		timeObserved := observations[t.Signal].time
		if !timeObserved.IsZero() {
			metrics.EvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInSeconds(timeObserved.Time))
			metrics.DeprecatedEvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInMicroseconds(timeObserved.Time))
		}
	}

	// we kill at most a single pod during each eviction interval
	for i := range activePods {
		pod := activePods[i]
		gracePeriodOverride := int64(0)
		if !isHardEvictionThreshold(thresholdToReclaim) {
			gracePeriodOverride = m.config.MaxPodGracePeriodSeconds
		}
		message, annotations := evictionMessage(resourceToReclaim, pod, statsFunc)
		if m.evictPod(pod, gracePeriodOverride, message, annotations) {
			return []*v1.Pod{pod}
		}
	}
	klog.Infof("eviction manager: unable to evict any pods from the node")
	return nil
}
```

带着我们文章上文提到的假设: eviction manager 获取对应的设置的驱逐策健值对,然后周期性的采集对应的内存和磁盘的时时使用数据, 然后和对应的资源设置的驱逐策略阈值进行比较, 如果达到驱逐的阈值, 则就根据驱逐的策略(可能是软硬同时存在),筛选出可驱逐的 pod,然后进行 pod 的停止,资源回收操作(可能包含容器和 image 等) 来看看这个方法是否是这样的逻辑处理呢?

1.

```
	thresholds := m.config.Thresholds
	if len(thresholds) == 0 && !utilfeature.DefaultFeatureGate.Enabled(features.LocalStorageCapacityIsolation) {
		return nil
	}
```

通过代码可以看出, 如果我们没有设置驱逐策略或者并且也没有开启这个 LocalStorageCapacityIsolation 功能,那 eviction manager 就不会做真正的驱逐逻辑处理,哪怕之前的 eviction manager 已经初始化,并且已经 start 了.

2.

```
	if m.dedicatedImageFs == nil {
		hasImageFs, ok := diskInfoProvider.HasDedicatedImageFs()
		if ok != nil {
			return nil
		}
		m.dedicatedImageFs = &hasImageFs
		m.signalToRankFunc = buildSignalToRankFunc(hasImageFs)
		m.signalToNodeReclaimFuncs = buildSignalToNodeReclaimFuncs(m.imageGC, m.containerGC, hasImageFs)
	}

```

接着是通过判断来设置 manager 是否使用专用的 imagefs, 设置 signalToRankFunc,signalToNodeReclaimFuncs, 我们看看这两个方法到底是干嘛的.

```
signalToRankFunc map[evictionapi.Signal]rankFunc 表一中的每种策略对应一个rankFunc,这个方法就是用来给满足驱逐的pod做评分排序的.

// rankFunc sorts the pods in eviction order
type rankFunc func(pods []*v1.Pod, stats statsFunc)

```

m.signalToRankFunc 的具体方法是 执行 buildSignalToRankFunc(hasImageFs)

```
// buildSignalToRankFunc returns ranking functions associated with resources
func buildSignalToRankFunc(withImageFs bool) map[evictionapi.Signal]rankFunc {
	signalToRankFunc := map[evictionapi.Signal]rankFunc{
		evictionapi.SignalMemoryAvailable:            rankMemoryPressure,
		evictionapi.SignalAllocatableMemoryAvailable: rankMemoryPressure,
		evictionapi.SignalPIDAvailable:               rankPIDPressure,
	}
	// usage of an imagefs is optional
	if withImageFs {
		// with an imagefs, nodefs pod rank func for eviction only includes logs and local volumes
		signalToRankFunc[evictionapi.SignalNodeFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalNodeFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
		// with an imagefs, imagefs pod rank func for eviction only includes rootfs
		signalToRankFunc[evictionapi.SignalImageFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalImageFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot}, resourceInodes)
	} else {
		// without an imagefs, nodefs pod rank func for eviction looks at all fs stats.
		// since imagefs and nodefs share a common device, they share common ranking functions.
		signalToRankFunc[evictionapi.SignalNodeFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalNodeFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
		signalToRankFunc[evictionapi.SignalImageFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalImageFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
	}
	return signalToRankFunc
}
```

这个方法中设置来根据是否是有来专有 imagefs 来设置不同的驱逐策略的 RankFunc,美中 RankFun 可以自己私下去细看,由于这块的代码有点复杂,所有我会在下一个文档中做非常详细的分析.

signalToNodeReclaimFuncs map[evictionapi.Signal]nodeReclaimFuncs 表一中的每种策略对应的资源回收的方法.

nodeReclaimFuncs // nodeReclaimFuncs is an ordered list of nodeReclaimFunc

type nodeReclaimFuncs []nodeReclaimFunc

signalToNodeReclaimFuncs 的具体方法是 执行 buildSignalToNodeReclaimFuncs(m.imageGC, m.containerGC, hasImageFs)

buildSignalToNodeReclaimFuncs

```
// buildSignalToNodeReclaimFuncs returns reclaim functions associated with resources.
func buildSignalToNodeReclaimFuncs(imageGC ImageGC, containerGC ContainerGC, withImageFs bool) map[evictionapi.Signal]nodeReclaimFuncs {
	signalToReclaimFunc := map[evictionapi.Signal]nodeReclaimFuncs{}
	// usage of an imagefs is optional
	if withImageFs {
		// with an imagefs, nodefs pressure should just delete logs
		signalToReclaimFunc[evictionapi.SignalNodeFsAvailable] = nodeReclaimFuncs{}
		signalToReclaimFunc[evictionapi.SignalNodeFsInodesFree] = nodeReclaimFuncs{}
		// with an imagefs, imagefs pressure should delete unused images
		signalToReclaimFunc[evictionapi.SignalImageFsAvailable] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
		signalToReclaimFunc[evictionapi.SignalImageFsInodesFree] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
	} else {
		// without an imagefs, nodefs pressure should delete logs, and unused images
		// since imagefs and nodefs share a common device, they share common reclaim functions
		signalToReclaimFunc[evictionapi.SignalNodeFsAvailable] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
		signalToReclaimFunc[evictionapi.SignalNodeFsInodesFree] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
		signalToReclaimFunc[evictionapi.SignalImageFsAvailable] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
		signalToReclaimFunc[evictionapi.SignalImageFsInodesFree] = nodeReclaimFuncs{containerGC.DeleteAllUnusedContainers, imageGC.DeleteUnusedImages}
	}
	return signalToReclaimFunc
}
```

资源的回收主要就是调用 imagegc 和 containergc 删除未使用的容器和镜像.

到此为止 eviction manager 所有需要的资源都已经准备就绪,接下来就是逻辑处理了.

```
	activePods := podFunc()
	updateStats := true
	summary, err := m.summaryProvider.Get(updateStats)
	if err != nil {
		klog.Errorf("eviction manager: failed to get summary stats: %v", err)
		return nil
	}
```

获取 running 的 pod,取得获取指标资源的 client(summary),等会儿后面用到这个 client 去获取资源的使用情况.

```
if m.clock.Since(m.thresholdsLastUpdated) > notifierRefreshInterval {
		m.thresholdsLastUpdated = m.clock.Now()
		for _, notifier := range m.thresholdNotifiers {
			if err := notifier.UpdateThreshold(summary); err != nil {
				klog.Warningf("eviction manager: failed to update %s: %v", notifier.Description(), err)
			}
		}
	}
```

如果上次运行 eviction manager 的所有事件(主要是资源超过设置的阈值事件)通知器的事件超过了通知器的通知周期,则运行所有的事通知器. 其实这里就一个事件通知器,就是当开启了 cgroup memory notifier 的时候创建的, 结合上面的**Start**方法的代码和如下代码:

```
func (m *memoryThresholdNotifier) Start() {
	klog.Infof("eviction manager: created %s", m.Description())
	for range m.events {
		m.handler(fmt.Sprintf("eviction manager: %s crossed", m.Description()))
	}
}

func (m *memoryThresholdNotifier) UpdateThreshold(summary *statsapi.Summary) error {
	memoryStats := summary.Node.Memory
	if isAllocatableEvictionThreshold(m.threshold) {
		allocatableContainer, err := getSysContainer(summary.Node.SystemContainers, statsapi.SystemContainerPods)
		if err != nil {
			return err
		}
		memoryStats = allocatableContainer.Memory
	}
	if memoryStats == nil || memoryStats.UsageBytes == nil || memoryStats.WorkingSetBytes == nil || memoryStats.AvailableBytes == nil {
		return fmt.Errorf("summary was incomplete.  Expected MemoryStats and all subfields to be non-nil, but got %+v", memoryStats)
	}
	// Set threshold on usage to capacity - eviction_hard + inactive_file,
	// since we want to be notified when working_set = capacity - eviction_hard
	inactiveFile := resource.NewQuantity(int64(*memoryStats.UsageBytes-*memoryStats.WorkingSetBytes), resource.BinarySI)
	capacity := resource.NewQuantity(int64(*memoryStats.AvailableBytes+*memoryStats.WorkingSetBytes), resource.BinarySI)
	evictionThresholdQuantity := evictionapi.GetThresholdQuantity(m.threshold.Value, capacity)
	memcgThreshold := capacity.DeepCopy()
	memcgThreshold.Sub(*evictionThresholdQuantity)
	memcgThreshold.Add(*inactiveFile)

	klog.V(3).Infof("eviction manager: setting %s to %s\n", m.Description(), memcgThreshold.String())
	if m.notifier != nil {
		m.notifier.Stop()
	}
	newNotifier, err := m.factory.NewCgroupNotifier(m.cgroupPath, memoryUsageAttribute, memcgThreshold.Value())
	if err != nil {
		return err
	}
	m.notifier = newNotifier
	go m.notifier.Start(m.events)
	return nil
}
```

UpdateThreshold 方法最终调用 m.notifier.Start(m.events) 方法,m.notifier.Start 方法中 m.handler(fmt.Sprintf("eviction manager: %s crossed", m.Description()))这个 m.handler 就是

```
	thresholdHandler := func(message string) {
		klog.Infof(message)
		m.synchronize(diskInfoProvider, podFunc)
	}

```

所以事件通知器最终还是调用 synchronize 方法去做驱逐处理,上面也说了,这个就是 eviction manager 真正做驱逐操作的核心方法.

```
	observations, statsFunc := makeSignalObservations(summary)
	debugLogObservations("observations", observations)
```

通过上面的资源获取的 client 去获取当前观察的资源值,以及返回一个获取 pod 状态的方法.

running pod 获取到了, 时时的资源值也获取到了, 接下来就是比较对应的值和设置策略阈值是否达到

```
	thresholds = thresholdsMet(thresholds, observations, false)
	debugLogThresholdsWithObservation("thresholds - ignoring grace period", thresholds, observations)

	// determine the set of thresholds previously met that have not yet satisfied the associated min-reclaim
	if len(m.thresholdsMet) > 0 {
		thresholdsNotYetResolved := thresholdsMet(m.thresholdsMet, observations, true)
		thresholds = mergeThresholds(thresholds, thresholdsNotYetResolved)
	}
	debugLogThresholdsWithObservation("thresholds - reclaim not satisfied", thresholds, observations)
```

```
// thresholdsMet returns the set of thresholds that were met independent of grace period
func thresholdsMet(thresholds []evictionapi.Threshold, observations signalObservations, enforceMinReclaim bool) []evictionapi.Threshold {
	results := []evictionapi.Threshold{}
	for i := range thresholds {
		threshold := thresholds[i]
		observed, found := observations[threshold.Signal]
		if !found {
			klog.Warningf("eviction manager: no observation found for eviction signal %v", threshold.Signal)
			continue
		}
		// determine if we have met the specified threshold
		thresholdMet := false
		quantity := evictionapi.GetThresholdQuantity(threshold.Value, observed.capacity)
		// if enforceMinReclaim is specified, we compare relative to value - minreclaim
		if enforceMinReclaim && threshold.MinReclaim != nil {
			quantity.Add(*evictionapi.GetThresholdQuantity(*threshold.MinReclaim, observed.capacity))
		}
		thresholdResult := quantity.Cmp(*observed.available)
		switch threshold.Operator {
		case evictionapi.OpLessThan:
			thresholdMet = thresholdResult > 0
		}
		if thresholdMet {
			results = append(results, threshold)
		}
	}
	return results
}
```

该方法具体通过获取时时的可用资源值和参数设置的阈值进比较,获取差值,如果大于设置的阈值,则返回需要驱逐的策略.

```
// track when a threshold was first observed
	now := m.clock.Now()
	thresholdsFirstObservedAt := thresholdsFirstObservedAt(thresholds, m.thresholdsFirstObservedAt, now)
```

记录下第一次 观察的时间

获取观察到的 node 状态

```
nodeConditions := nodeConditions(thresholds)
	if len(nodeConditions) > 0 {
		klog.V(3).Infof("eviction manager: node conditions - observed: %v", nodeConditions)
	}

	// track when a node condition was last observed
	nodeConditionsLastObservedAt := nodeConditionsLastObservedAt(nodeConditions, m.nodeConditionsLastObservedAt, now)

	// node conditions report true if it has been observed within the transition period window
	nodeConditions = nodeConditionsObservedSince(nodeConditionsLastObservedAt, m.config.PressureTransitionPeriod, now)
	if len(nodeConditions) > 0 {
		klog.V(3).Infof("eviction manager: node conditions - transition period not met: %v", nodeConditions)
	}
```

然后记给所有的到达阈值的策略设置上优雅回收时间并且跟新 eviction manager 的 node 状态,策略阈值,首次获取 node 状态和资源使用的时间.

```
thresholds = thresholdsMetGracePeriod(thresholdsFirstObservedAt, now)
	debugLogThresholdsWithObservation("thresholds - grace periods satisified", thresholds, observations)

	// update internal state
	m.Lock()
	m.nodeConditions = nodeConditions
	m.thresholdsFirstObservedAt = thresholdsFirstObservedAt
	m.nodeConditionsLastObservedAt = nodeConditionsLastObservedAt
	m.thresholdsMet = thresholds

	// determine the set of thresholds whose stats have been updated since the last sync
	thresholds = thresholdsUpdatedStats(thresholds, observations, m.lastObservations)
	debugLogThresholdsWithObservation("thresholds - updated stats", thresholds, observations)

	m.lastObservations = observations
	m.Unlock()
```

排序达到阈值的策略

```
sort.Sort(byEvictionPriority(thresholds))
	thresholdToReclaim := thresholds[0]
	resourceToReclaim, found := signalToResource[thresholdToReclaim.Signal]
	if !found {
		klog.V(3).Infof("eviction manager: threshold %s was crossed, but reclaim is not implemented for this threshold.", thresholdToReclaim.Signal)
		return nil
	}
	klog.Warningf("eviction manager: attempting to reclaim %v", resourceToReclaim)

	// record an event about the resources we are now attempting to reclaim via eviction
	m.recorder.Eventf(m.nodeRef, v1.EventTypeWarning, "EvictionThresholdMet", "Attempting to reclaim %s", resourceToReclaim)


	// check if there are node-level resources we can reclaim to reduce pressure before evicting end-user pods.
	if m.reclaimNodeLevelResources(thresholdToReclaim.Signal, resourceToReclaim) {
		klog.Infof("eviction manager: able to reduce %v pressure without evicting pods.", resourceToReclaim)
		return nil
	}

```

```
// reclaimNodeLevelResources attempts to reclaim node level resources.  returns true if thresholds were satisfied and no pod eviction is required.
func (m *managerImpl) reclaimNodeLevelResources(signalToReclaim evictionapi.Signal, resourceToReclaim v1.ResourceName) bool {
	nodeReclaimFuncs := m.signalToNodeReclaimFuncs[signalToReclaim]
	for _, nodeReclaimFunc := range nodeReclaimFuncs {
		// attempt to reclaim the pressured resource.
		if err := nodeReclaimFunc(); err != nil {
			klog.Warningf("eviction manager: unexpected error when attempting to reduce %v pressure: %v", resourceToReclaim, err)
		}

	}
	if len(nodeReclaimFuncs) > 0 {
		summary, err := m.summaryProvider.Get(true)
		if err != nil {
			klog.Errorf("eviction manager: failed to get summary stats after resource reclaim: %v", err)
			return false
		}

		// make observations and get a function to derive pod usage stats relative to those observations.
		observations, _ := makeSignalObservations(summary)
		debugLogObservations("observations after resource reclaim", observations)

		// determine the set of thresholds met independent of grace period
		thresholds := thresholdsMet(m.config.Thresholds, observations, false)
		debugLogThresholdsWithObservation("thresholds after resource reclaim - ignoring grace period", thresholds, observations)

		if len(thresholds) == 0 {
			return true
		}
	}
	return false
}
```

thresholds 排序规则: allocatableMemory.available,memory.available,nodefs.available,nodefs.inodesFree,imagefs.available,imagefs.inodesFree,pid.available

然后获取第 0 个策略, 进行 node 级别的资源回收(只有这两个 nodefs.available,nodefs.inodesFree),如果没有 node 级别的资源回收就返回, 也就是说当我们同时设置了 allocatableMemory.available,memory.available,nodefs.available,nodefs.inodesFree,imagefs.available,imagefs.inodesFree,pid.available 其中的一个或者多个的时候, 如果其中有多个值达到阈值, 则每次回收只回收一种策略的(级别最高的那中策略),而且可能最高的那个策略就是 node 级别的策略,那这样的话,我们就可以不用驱逐 pod 就可以降低 node 策略资源的压力.

最后处理回收 pod 级别的资源

```go
	// rank the pods for eviction
	rank, ok := m.signalToRankFunc[thresholdToReclaim.Signal]
	if !ok {
		klog.Errorf("eviction manager: no ranking function for signal %s", thresholdToReclaim.Signal)
		return nil
	}

	// the only candidates viable for eviction are those pods that had anything running.
	if len(activePods) == 0 {
		klog.Errorf("eviction manager: eviction thresholds have been met, but no pods are active to evict")
		return nil
	}

	// rank the running pods for eviction for the specified resource
	rank(activePods, statsFunc)

	klog.Infof("eviction manager: pods ranked for eviction: %s", format.Pods(activePods))

	//record age of metrics for met thresholds that we are using for evictions.
	for _, t := range thresholds {
		timeObserved := observations[t.Signal].time
		if !timeObserved.IsZero() {
			metrics.EvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInSeconds(timeObserved.Time))
			metrics.DeprecatedEvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInMicroseconds(timeObserved.Time))
		}
	}

```

首先获取对应策略的排序方法来排序需要回收的 pod.

```
	// we kill at most a single pod during each eviction interval
	for i := range activePods {
		pod := activePods[i]
		gracePeriodOverride := int64(0)
		if !isHardEvictionThreshold(thresholdToReclaim) {
			gracePeriodOverride = m.config.MaxPodGracePeriodSeconds
		}
		message, annotations := evictionMessage(resourceToReclaim, pod, statsFunc)
		if m.evictPod(pod, gracePeriodOverride, message, annotations) {
			return []*v1.Pod{pod}
		}
	}
	klog.Infof("eviction manager: unable to evict any pods from the node")
	return nil
```

然后设置优雅回收时间,之后调用 evictPod 方法驱逐 pod。请注意 activePods 的 for 循环如果第一个 pod 驱逐成功，直接返回驱逐的 pod 信息，如果不成功，则选择下一个 pod 进行驱逐，也就是说，每个驱逐周期内，只会驱逐一个 pod。

```

func (m *managerImpl) evictPod(pod *v1.Pod, gracePeriodOverride int64, evictMsg string, annotations map[string]string) bool {
	// If the pod is marked as critical and static, and support for critical pod annotations is enabled,
	// do not evict such pods. Static pods are not re-admitted after evictions.
	// https://github.com/kubernetes/kubernetes/issues/40573 has more details.
	if kubepod.IsStaticPod(pod) {
		// need mirrorPod to check its "priority" value; static pod doesn't carry it
		if mirrorPod, ok := m.mirrorPodFunc(pod); ok && mirrorPod != nil {
			// skip only when it's a static and critical pod
			if kubelettypes.IsCriticalPod(mirrorPod) {
				klog.Errorf("eviction manager: cannot evict a critical static pod %s", format.Pod(pod))
				return false
			}
		} else {
			// we should never hit this
			klog.Errorf("eviction manager: cannot get mirror pod from static pod %s, so cannot evict it", format.Pod(pod))
			return false
		}
	}
	status := v1.PodStatus{
		Phase:   v1.PodFailed,
		Message: evictMsg,
		Reason:  Reason,
	}
	// record that we are evicting the pod
	m.recorder.AnnotatedEventf(pod, annotations, v1.EventTypeWarning, Reason, evictMsg)
	// this is a blocking call and should only return when the pod and its containers are killed.
	err := m.killPodFunc(pod, status, &gracePeriodOverride)
	if err != nil {
		klog.Errorf("eviction manager: pod %s failed to evict %v", format.Pod(pod), err)
	} else {
		klog.Infof("eviction manager: pod %s is evicted successfully", format.Pod(pod))
	}
	return true
}
```

mirro pod 的处理，然后是调用 killPodFunc 杀死 pod 从而达到驱逐的目的。

## 核心代码

整体的代码流程我们分析完了，那接下来我们看看其中比较核心的几个 rank 方法。分两类，一类是 threthos 用到的，一类是 pod 用到的。

### Threshold Rank

```go
// byEvictionPriority implements sort.Interface for []v1.ResourceName.
type byEvictionPriority []evictionapi.Threshold

func (a byEvictionPriority) Len() int { return len(a) }
func (a byEvictionPriority) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less ranks memory before all other resources, and ranks thresholds with no resource to reclaim last
func (a byEvictionPriority) Less(i, j int) bool {
\_, jSignalHasResource := signalToResource[a[j].Signal]
return a[i].Signal == evictionapi.SignalMemoryAvailable || a[i].Signal == evictionapi.SignalAllocatableMemoryAvailable || !jSignalHasResource
}
```

byEvictionPriority 这是一个 evictionapi.Threshold 的数组，它实现了 golang 的 sort 包中的 Interface 接口，也就是排序的接口。核心逻辑就在 Less 方法中，也非常简单。当所有的策略都设置的时候排序的结果如下：allocatableMemory.available，memory.available，nodefs.available，nodefs.inodesFree，imagefs.available，imagefs.inodesFree，pid.available

### Pod Rank

上文我们分析过了，eviction manager 的 signalToRankFunc 是通过 buildSignalToRankFunc 这个方法创建，那我们先来看看这个方法

```go
// buildSignalToRankFunc returns ranking functions associated with resources
func buildSignalToRankFunc(withImageFs bool) map[evictionapi.Signal]rankFunc {
	signalToRankFunc := map[evictionapi.Signal]rankFunc{
		evictionapi.SignalMemoryAvailable:            rankMemoryPressure,
		evictionapi.SignalAllocatableMemoryAvailable: rankMemoryPressure,
		evictionapi.SignalPIDAvailable:               rankPIDPressure,
	}
	// usage of an imagefs is optional
	if withImageFs {
		// with an imagefs, nodefs pod rank func for eviction only includes logs and local volumes
		signalToRankFunc[evictionapi.SignalNodeFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalNodeFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
		// with an imagefs, imagefs pod rank func for eviction only includes rootfs
		signalToRankFunc[evictionapi.SignalImageFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalImageFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot}, resourceInodes)
	} else {
		// without an imagefs, nodefs pod rank func for eviction looks at all fs stats.
		// since imagefs and nodefs share a common device, they share common ranking functions.
		signalToRankFunc[evictionapi.SignalNodeFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalNodeFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
		signalToRankFunc[evictionapi.SignalImageFsAvailable] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, v1.ResourceEphemeralStorage)
		signalToRankFunc[evictionapi.SignalImageFsInodesFree] = rankDiskPressureFunc([]fsStatsType{fsStatsRoot, fsStatsLogs, fsStatsLocalVolumeSource}, resourceInodes)
	}
	return signalToRankFunc
}
```

这个方法中包含来每一种策略对应的 rank 方法的实现指定。接下来我们分析下具体的每种实现

```go
// rankMemoryPressure orders the input pods for eviction in response to memory pressure.
// It ranks by whether or not the pod's usage exceeds its requests, then by priority, and
// finally by memory usage above requests.
func rankMemoryPressure(pods []*v1.Pod, stats statsFunc) {
	orderedBy(exceedMemoryRequests(stats), priority, memory(stats)).Sort(pods)
}

// rankPIDPressure orders the input pods by priority in response to PID pressure.
func rankPIDPressure(pods []*v1.Pod, stats statsFunc) {
	orderedBy(priority).Sort(pods)
}

// rankDiskPressureFunc returns a rankFunc that measures the specified fs stats.
func rankDiskPressureFunc(fsStatsToMeasure []fsStatsType, diskResource v1.ResourceName) rankFunc {
	return func(pods []*v1.Pod, stats statsFunc) {
		orderedBy(exceedDiskRequests(stats, fsStatsToMeasure, diskResource), priority, disk(stats, fsStatsToMeasure, diskResource)).Sort(pods)
	}
}
```

在具体分析三个方法前我们先看看如下这段代码，因为这以上三个方法都是基于如下这段代码中的实现写的

```go
type cmpFunc func(p1, p2 *v1.Pod) int

// multiSorter implements the Sort interface, sorting changes within.
type multiSorter struct {
	pods []*v1.Pod
	cmp  []cmpFunc
}

// Sort sorts the argument slice according to the less functions passed to OrderedBy.
func (ms *multiSorter) Sort(pods []*v1.Pod) {
	ms.pods = pods
	sort.Sort(ms)
}

// OrderedBy returns a Sorter that sorts using the cmp functions, in order.
// Call its Sort method to sort the data.
func orderedBy(cmp ...cmpFunc) *multiSorter {
	return &multiSorter{
		cmp: cmp,
	}
}

// Len is part of sort.Interface.
func (ms *multiSorter) Len() int {
	return len(ms.pods)
}

// Swap is part of sort.Interface.
func (ms *multiSorter) Swap(i, j int) {
	ms.pods[i], ms.pods[j] = ms.pods[j], ms.pods[i]
}

// Less is part of sort.Interface.
func (ms *multiSorter) Less(i, j int) bool {
	p1, p2 := ms.pods[i], ms.pods[j]
	var k int
	for k = 0; k < len(ms.cmp)-1; k++ {
		cmpResult := ms.cmp[k](p1, p2)
		// p1 is less than p2
		if cmpResult < 0 {
			return true
		}
		// p1 is greater than p2
		if cmpResult > 0 {
			return false
		}
		// we don't know yet
	}
	// the last cmp func is the final decider
	return ms.cmp[k](p1, p2) < 0
}
```

multiSorter 有两个 field，一个是 pods 数组，需要排序的数组，一个 cmpFunc 数组，就是比较两个 pod 大小的方法。multiSorter 实现了 sort.Interface 接口从而实现了 pod 排序。而在排序中，Less 方法是核心，逻辑如下：将 multiSorter 中的比较方法挨个执行，获取 a，b 差值，如果相等，继续执行下一个，如果不相等，返回比较结过，如果前面的 n-1 个 cmpFunc 多执行完了，a,b 还是相等，那就执行最后一个 cmpFunc。

然后我们来看看 地段代码中用到的 cmpFunc 有如下几个：exceedMemoryRequests，priority，memory，disk，exceedDiskRequests

rankMemoryPressure 用到 exceedMemoryRequests，priority，memory

rankPIDPressure 用到 priority

rankDiskPressureFunc 用到 exceedDiskRequests，priority，disk

接下来我们来具体分析每一个 cmpFunc

#### cmpFunc 分析

##### exceedMemoryRequests

```go
// exceedMemoryRequests compares whether or not pods' memory usage exceeds their requests
func exceedMemoryRequests(stats statsFunc) cmpFunc {
	return func(p1, p2 *v1.Pod) int {
		p1Stats, p1Found := stats(p1)
		p2Stats, p2Found := stats(p2)
		if !p1Found || !p2Found {
			// prioritize evicting the pod for which no stats were found
			return cmpBool(!p1Found, !p2Found)
		}

		p1Memory := memoryUsage(p1Stats.Memory)
		p2Memory := memoryUsage(p2Stats.Memory)
		p1ExceedsRequests := p1Memory.Cmp(podRequest(p1, v1.ResourceMemory)) == 1
		p2ExceedsRequests := p2Memory.Cmp(podRequest(p2, v1.ResourceMemory)) == 1
		// prioritize evicting the pod which exceeds its requests
		return cmpBool(p1ExceedsRequests, p2ExceedsRequests)
	}
}
```

该方法也相对简单， 就是分别获取两个 pod 的当前内存使用值（细看会发现这个使用值是内存的 workset 值，什么是 workset 值呢，相关字段的注释：// The amount of working set memory. This includes recently accessed memory,
// dirty memory, and kernel memory. WorkingSetBytes is <= UsageBytes 我自己的理解翻译应该是当前时间，pod 所使用的内存，包活垃圾内存，内核内存），然后分别比较使用值和对应 pod 的 request 值的大小，判断是否前使用内存超过了 request 内存值，然后返回是否两个 pod 都超过了 request 内存值。

##### priority

```go
// priority compares pods by Priority, if priority is enabled.
func priority(p1, p2 *v1.Pod) int {
	if !utilfeature.DefaultFeatureGate.Enabled(features.PodPriority) {
		// If priority is not enabled, all pods are equal.
		return 0
	}
	priority1 := schedulerutils.GetPodPriority(p1)
	priority2 := schedulerutils.GetPodPriority(p2)
	if priority1 == priority2 {
		return 0
	}
	if priority1 > priority2 {
		return 1
	}
	return -1
}
```

priority 如果开启了 pod 优先级功能，则比较两个 pod 的优先级（pod.Spec.Priority，该值不能用户手动设置，只有当 pod 设置了 PriorityClassName 时，k8s 系统组件自己通过获取对应的 PriorityClass 设置的对应的优先级的值来设置该字段的值），优先级越高的越不容易被驱逐，优先级越低的越容器被驱逐。

##### memory

```go
// memory compares pods by largest consumer of memory relative to request.
func memory(stats statsFunc) cmpFunc {
	return func(p1, p2 *v1.Pod) int {
		p1Stats, p1Found := stats(p1)
		p2Stats, p2Found := stats(p2)
		if !p1Found || !p2Found {
			// prioritize evicting the pod for which no stats were found
			return cmpBool(!p1Found, !p2Found)
		}

		// adjust p1, p2 usage relative to the request (if any)
		p1Memory := memoryUsage(p1Stats.Memory)
		p1Request := podRequest(p1, v1.ResourceMemory)
		p1Memory.Sub(p1Request)

		p2Memory := memoryUsage(p2Stats.Memory)
		p2Request := podRequest(p2, v1.ResourceMemory)
		p2Memory.Sub(p2Request)

		// prioritize evicting the pod which has the larger consumption of memory
		return p2Memory.Cmp(*p1Memory)
	}
}
```

该方法实现的逻辑也比较简单，就是判断 pod1 和 pod2 谁的 memoryUsage-memoryRequest 的差值谁大谁小。

##### disk

```go
// disk compares pods by largest consumer of disk relative to request for the specified disk resource.
func disk(stats statsFunc, fsStatsToMeasure []fsStatsType, diskResource v1.ResourceName) cmpFunc {
	return func(p1, p2 *v1.Pod) int {
		p1Stats, p1Found := stats(p1)
		p2Stats, p2Found := stats(p2)
		if !p1Found || !p2Found {
			// prioritize evicting the pod for which no stats were found
			return cmpBool(!p1Found, !p2Found)
		}
		p1Usage, p1Err := podDiskUsage(p1Stats, p1, fsStatsToMeasure)
		p2Usage, p2Err := podDiskUsage(p2Stats, p2, fsStatsToMeasure)
		if p1Err != nil || p2Err != nil {
			// prioritize evicting the pod which had an error getting stats
			return cmpBool(p1Err != nil, p2Err != nil)
		}

		// adjust p1, p2 usage relative to the request (if any)
		p1Disk := p1Usage[diskResource]
		p2Disk := p2Usage[diskResource]
		p1Request := podRequest(p1, v1.ResourceEphemeralStorage)
		p1Disk.Sub(p1Request)
		p2Request := podRequest(p2, v1.ResourceEphemeralStorage)
		p2Disk.Sub(p2Request)
		// prioritize evicting the pod which has the larger consumption of disk
		return p2Disk.Cmp(p1Disk)
	}
}

// podDiskUsage aggregates pod disk usage and inode consumption for the specified stats to measure.
func podDiskUsage(podStats statsapi.PodStats, pod *v1.Pod, statsToMeasure []fsStatsType) (v1.ResourceList, error) {
	disk := resource.Quantity{Format: resource.BinarySI}
	inodes := resource.Quantity{Format: resource.DecimalSI}

	containerUsageList := containerUsage(podStats, statsToMeasure)
	disk.Add(containerUsageList[v1.ResourceEphemeralStorage])
	inodes.Add(containerUsageList[resourceInodes])

	if hasFsStatsType(statsToMeasure, fsStatsLocalVolumeSource) {
		volumeNames := localVolumeNames(pod)
		podLocalVolumeUsageList := podLocalVolumeUsage(volumeNames, podStats)
		disk.Add(podLocalVolumeUsageList[v1.ResourceEphemeralStorage])
		inodes.Add(podLocalVolumeUsageList[resourceInodes])
	}
	return v1.ResourceList{
		v1.ResourceEphemeralStorage: disk,
		resourceInodes:              inodes,
	}, nil
}
```

该方法是比较 pod1 pod2 请求值减使用值（包括 pod 使用的 localvolume，包括 绑定 emptydir configmap secret，hostpath 所产生的文件 以及日志文件）的大小

##### exceedDiskRequests

```go
// exceedDiskRequests compares whether or not pods' disk usage exceeds their requests
func exceedDiskRequests(stats statsFunc, fsStatsToMeasure []fsStatsType, diskResource v1.ResourceName) cmpFunc {
	return func(p1, p2 *v1.Pod) int {
		p1Stats, p1Found := stats(p1)
		p2Stats, p2Found := stats(p2)
		if !p1Found || !p2Found {
			// prioritize evicting the pod for which no stats were found
			return cmpBool(!p1Found, !p2Found)
		}

		p1Usage, p1Err := podDiskUsage(p1Stats, p1, fsStatsToMeasure)
		p2Usage, p2Err := podDiskUsage(p2Stats, p2, fsStatsToMeasure)
		if p1Err != nil || p2Err != nil {
			// prioritize evicting the pod which had an error getting stats
			return cmpBool(p1Err != nil, p2Err != nil)
		}

		p1Disk := p1Usage[diskResource]
		p2Disk := p2Usage[diskResource]
		p1ExceedsRequests := p1Disk.Cmp(podRequest(p1, diskResource)) == 1
		p2ExceedsRequests := p2Disk.Cmp(podRequest(p2, diskResource)) == 1
		// prioritize evicting the pod which exceeds its requests
		return cmpBool(p1ExceedsRequests, p2ExceedsRequests)
	}
}
```

该方法通过判断 pod1 pod2 使用的磁盘值是否超过请求值

综合上述的方法分析，那我们可以做如下的总结：
排序 pod，最终更 pod 的 Priority，是否超过 request，内存使用与 request 差值有关。

优先级最低，内存差值（usage-requst）越大，越先被驱逐。通过分析
